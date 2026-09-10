#!/usr/bin/env python3
# Stdlib-only harness (no external deps, matching wizlab). Locks the load-bearing invariants so
# refactors are safe without re-playing a lab: the 0/1/2/3 exit-code contract, IAM-trust parsing
# breadth, flag edges, and the main() dispatch guard. Run: python wizlab/test_wizlab.py
import base64
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import tempfile
import types
import typing
import unittest
import urllib.error
from importlib.machinery import SourceFileLoader
from unittest import mock

_spec = importlib.util.spec_from_loader(
    "wizlab_cli", SourceFileLoader("wizlab_cli", str(pathlib.Path(__file__).resolve().parent / "wizlab")))
wz = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wz)

# `_keypair_dir` falls back to ~/.cache/wizlab/lease/<lab>, and the lease tests name a REAL lab
# (te-dev-aws), so a suite run on an operator's box deleted the private key of a live play and still
# exited OK — the play stays up, unreachable, and no new pubkey can reach a container that read the
# secret at sandbox build. Redirect for the whole process, not per test: three tests escaped a
# per-test tempdir unnoticed, and the next one added would too.
_LEASE_SANDBOX = tempfile.TemporaryDirectory()
os.environ["WIZLAB_LEASE_DIR"] = _LEASE_SANDBOX.name


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _trust(delegator, external_id, op="StringEquals", key="sts:ExternalId", action="sts:AssumeRole"):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": delegator},
            "Action": action,
            "Condition": {op: {key: external_id}},
        }],
    }


class _Ended:
    code = None


@contextlib.contextmanager
def exits():
    """The suite's one statement of how a handler ends: `.code` is what main() would exit with. A
    WizlabError is reported the way main() reports it, a learner-state sys.exit passes its code through,
    and a plain return is 0."""
    ended = _Ended()
    try:
        yield ended
    except wz.WizlabError as e:
        ended.code = wz._fail(e)
    except SystemExit as e:
        ended.code = e.code
    else:
        ended.code = 0


def _jwt(**claims):
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"h.{body}.s"


class FakeWiz:
    """A tenant behind _post: mints a token for AUTH_URL and answers GraphQL by the top-level field of
    the document, so a test names the server object that answers, not a substring of our own document.
    `fields` values: a dict is that field's payload, a callable takes the variables and returns it, a
    `FakeWiz.error(msg)` is a GraphQL error. Unlisted fields answer {}. `calls` holds (field, variables)
    per request and `docs` the raw documents, so a test can assert what left the process."""
    ENV: typing.ClassVar = {"WIZ_CLIENT_ID": "cid", "WIZ_CLIENT_SECRET": "sec"}
    _FIELD = re.compile(r"^\s*(?:query|mutation)\b[^{]*\{\s*(\w+)|^\s*\{\s*(\w+)")

    class error:
        def __init__(self, message):
            self.message = message

    def __init__(self, tid="tid", **fields):
        self.tid, self.fields, self.calls, self.docs, self.mints = tid, fields, [], [], 0

    def __call__(self, url, data, headers, attempts=3):
        if url == wz.AUTH_URL:
            self.mints += 1
            return {"access_token": _jwt(dc="dc", tid=self.tid, exp=int(wz.time.time()) + 3600)}
        m = self._FIELD.match(data["query"])
        field, variables = m.group(1) or m.group(2), data.get("variables") or {}
        self.calls.append((field, variables))
        self.docs.append(data["query"])
        answer = self.fields.get(field, {})
        if callable(answer):
            answer = answer(variables)
        if isinstance(answer, FakeWiz.error):
            return {"errors": [{"message": answer.message}], "data": None}
        return {"data": {field: answer}}

    def sent(self, field):
        return [v for f, v in self.calls if f == field]


def exit_code(fn, argv=(), *, wiz=None, env=None, out=None, err=None, **patches):
    """Drive one handler as main() would and return its exit code. Output is captured into `out`/`err`
    or dropped. `env` replaces the environment. `patches` name wz attributes: a Mock replaces the
    attribute, another callable is its side_effect, anything else its return_value. `wiz` is a FakeWiz
    behind _post, with the credentials token_and_dc reads."""
    wz._TOKENS.clear()
    with contextlib.ExitStack() as st:
        if wiz is not None:
            env = {**(os.environ if env is None else env), **FakeWiz.ENV}
            st.enter_context(mock.patch.object(wz, "_post", wiz))
        if env is not None:
            st.enter_context(mock.patch.dict(wz.os.environ, env, clear=True))
        for name, value in patches.items():
            if isinstance(value, mock.Mock):
                st.enter_context(mock.patch.object(wz, name, value))
            elif callable(value):
                st.enter_context(mock.patch.object(wz, name, side_effect=value))
            else:
                st.enter_context(mock.patch.object(wz, name, return_value=value))
        st.enter_context(contextlib.redirect_stdout(io.StringIO() if out is None else out))
        st.enter_context(contextlib.redirect_stderr(io.StringIO() if err is None else err))
        with exits() as ended:
            fn(list(argv))
    return ended.code


class PureParsing(unittest.TestCase):
    def test_as_list(self):
        self.assertEqual(wz._as_list(None), [])
        self.assertEqual(wz._as_list("x"), ["x"])
        self.assertEqual(wz._as_list(["a", "b"]), ["a", "b"])

    def test_principals(self):
        self.assertEqual(wz._principals({"Principal": "svc"}), ["svc"])
        self.assertEqual(wz._principals({"Principal": {"AWS": ["a", "b"]}}), ["a", "b"])
        self.assertEqual(wz._principals({}), [])

    def test_grants_assume_role(self):
        for a in ("sts:AssumeRole", "sts:*", "*", "sts:Assume*"):
            self.assertTrue(wz._grants_assume_role({"Effect": "Allow", "Action": a}), a)
        self.assertFalse(wz._grants_assume_role({"Effect": "Deny", "Action": "sts:AssumeRole"}))
        self.assertFalse(wz._grants_assume_role({"Effect": "Allow", "Action": "s3:GetObject"}))

    def test_external_ids_operator_variants(self):
        # Breadth is load-bearing: every equality variant must be caught, or a role Wiz can assume
        # gets mis-graded as "no external id". StringLike must NOT match (it doesn't pin the value).
        tid = "6ca852a0"
        for op in ("StringEquals", "StringEqualsIgnoreCase", "ForAllValues:StringEquals"):
            stmt = _trust("d", tid, op=op)["Statement"][0]
            self.assertEqual(wz._external_ids(stmt), [tid], op)
        for key in ("sts:ExternalId", "STS:EXTERNALID", " sts:externalid "):
            stmt = _trust("d", tid, key=key)["Statement"][0]
            self.assertEqual(wz._external_ids(stmt), [tid], key)
        self.assertEqual(wz._external_ids(_trust("d", tid, op="StringLike")["Statement"][0]), [])

    def test_decode_trust_policy(self):
        pol = _trust("d", "x")
        self.assertEqual(wz._decode_trust_policy(pol), pol)                       # dict passthrough
        self.assertEqual(wz._decode_trust_policy(json.dumps(pol)), pol)           # json string
        self.assertEqual(wz._decode_trust_policy(urllib.parse.quote(json.dumps(pol))), pol)  # %-encoded
        self.assertIsNone(wz._decode_trust_policy("not json"))


class FlagParsing(unittest.TestCase):
    def test_present_and_absent(self):
        self.assertEqual(wz._flag(["--account-id", "123"], "--account-id"), "123")
        self.assertIsNone(wz._flag(["--other", "v"], "--account-id"))

    def test_missing_value_is_invocation_error(self):
        with exits() as cm:
            wz._flag(["role", "inspect", "--role-name"], "--role-name")
        self.assertEqual(cm.code, 2)

    def test_the_next_flag_is_never_the_value(self):
        # `reap --session --commit` must not reap a session named "--commit" with commit silently off.
        with exits() as cm:
            wz._flag(["--session", "--commit"], "--session")
        self.assertEqual(cm.code, 2)


class CliHelper(unittest.TestCase):
    def test_missing_binary_is_environment_3(self):
        # FileNotFoundError must map to exit 3, not bubble as an uncaught exception (which would be 2).
        with mock.patch.object(wz.subprocess, "run", side_effect=FileNotFoundError), \
             exits() as cm:
            wz._cli("no-such-binary", "version")
        self.assertEqual(cm.code, 3)

    def test_aws_gcp_az_delegate_to_cli(self):
        proc = _proc(0, "ok")
        with mock.patch.object(wz, "_cli", return_value=proc) as cli:
            wz._aws("sts", "get-caller-identity")
            wz._gcp("auth", "list")
            wz._az("account", "show")
        calls = [c[0] for c in cli.call_args_list]
        self.assertEqual(calls[0][0], "aws")
        self.assertEqual(calls[1][0], "gcloud")
        self.assertEqual(calls[2][0], "az")


    def test_a_hung_binary_is_environment_3(self):
        with mock.patch.object(wz.subprocess, "run",
                               side_effect=wz.subprocess.TimeoutExpired("aws", wz._CLI_TIMEOUT_S)), \
             exits() as cm:
            wz._cli("aws", "sts", "get-caller-identity")
        self.assertEqual(cm.code, 3)


class ExitCodeContract(unittest.TestCase):
    def _urlopen_returning(self, body):
        cm = mock.MagicMock()
        cm.__enter__.return_value.read.return_value = body
        return mock.MagicMock(return_value=cm)

    def test_post_success(self):
        with mock.patch.object(wz.urllib.request, "urlopen", self._urlopen_returning(b'{"ok": true}')):
            self.assertEqual(wz._post("https://x/", "d", {}), {"ok": True})

    def test_post_transport_retries_then_exit_3(self):
        op = mock.MagicMock(side_effect=urllib.error.URLError("boom"))
        with mock.patch.object(wz.urllib.request, "urlopen", op), mock.patch.object(wz.time, "sleep"), \
             exits() as cm:
            wz._post("https://x/", "d", {}, attempts=3)
        self.assertEqual(cm.code, 3)
        self.assertEqual(op.call_count, 3)  # retried, not one-shot

    def test_post_4xx_fails_fast(self):
        err = urllib.error.HTTPError("u", 400, "bad", None, io.BytesIO(b"nope"))
        op = mock.MagicMock(side_effect=err)
        with mock.patch.object(wz.urllib.request, "urlopen", op), mock.patch.object(wz.time, "sleep"), \
             exits() as cm:
            wz._post("https://x/", "d", {}, attempts=3)
        self.assertEqual(cm.code, 3)
        self.assertEqual(op.call_count, 1)  # 4xx is not transient — no retry

    def test_main_bad_verb_is_invocation_error(self):
        with mock.patch.object(wz.sys, "argv", ["wizlab", "bogus", "verb"]), exits() as cm:
            wz.main()
        self.assertEqual(cm.code, 2)

    def test_main_guards_uncaught_exception_as_2(self):
        boom = mock.MagicMock(side_effect=RuntimeError("kaboom"))
        with mock.patch.dict(wz.VERBS, {("session", "verify"): boom}), \
             mock.patch.object(wz.sys, "argv", ["wizlab", "session", "verify"]), \
             exits() as cm:
            wz.main()
        self.assertEqual(cm.code, 2)  # bug, not a raw traceback exiting 1

    def test_a_handler_that_returns_is_exit_0(self):
        # The contract main() adopts when handlers stop calling sys.exit: a plain return is success.
        self.assertEqual(exit_code(lambda argv: None, []), 0)
        self.assertEqual(exit_code(lambda argv: wz.die(3, "x"), []), 3)

    def test_the_fake_tenant_drives_the_real_transport(self):
        # A GraphQL error from the tenant reaches the handler through api(), not through a patched api.
        wiz = FakeWiz(deployments=FakeWiz.error("denied"))
        err = io.StringIO()
        code = exit_code(wz.cmd_serviceaccount_inspect, ["--name", "lab-x"], wiz=wiz, err=err)
        self.assertEqual(code, 3)
        self.assertIn("denied", err.getvalue())
        self.assertEqual([f for f, _ in wiz.calls], ["deployments"])

    def test_main_reports_a_wizlab_error_once_with_its_code(self):
        err = io.StringIO()
        with mock.patch.object(wz.sys, "argv", ["wizlab", "policy", "inspect"]), \
             contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            wz.main()
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(err.getvalue().count("wizlab:"), 1)
        self.assertIn("--name", err.getvalue())

    def test_main_exits_0_when_the_handler_returns(self):
        with mock.patch.dict(wz.VERBS, {("session", "verify"): lambda argv: None}), \
             mock.patch.object(wz.sys, "argv", ["wizlab", "session", "verify"]):
            self.assertIsNone(wz.main())

    def test_one_token_serves_every_call_in_a_process(self):
        # session verify used to mint twice back to back; the cache holds until a minute before `exp`.
        wiz = FakeWiz(connectors={"totalCount": 0})
        self.assertEqual(exit_code(wz.cmd_session_verify, [], wiz=wiz), 0)
        self.assertEqual(wiz.mints, 1)
        self.assertGreaterEqual(len(wiz.calls), 1)

    def test_an_expiring_token_is_reminted(self):
        wiz, clock = FakeWiz(), {"t": 1000.0}
        with mock.patch.object(wz, "_post", wiz), mock.patch.dict(wz.os.environ, FakeWiz.ENV, clear=True), \
             mock.patch.object(wz.time, "time", lambda: clock["t"]):
            wz._TOKENS.clear()
            wz.token_and_dc()
            wz.token_and_dc()
            self.assertEqual(wiz.mints, 1)
            clock["t"] += 3600 - 30  # inside the minute before exp
            wz.token_and_dc()
        self.assertEqual(wiz.mints, 2)
        wz._TOKENS.clear()

    def test_user_inspect_group_transport_failure_is_environment_3(self):
        session = wz._KcSession("https://kc", "realm", "tok", "lab-s1@example.com", "lab-s1")
        with mock.patch.object(wz, "_kc_session", return_value=session), \
             mock.patch.object(wz, "_kc_user_id", return_value="u1"), \
             mock.patch.object(wz, "_kc_call", return_value=(503, b"unavailable")), \
             exits() as cm:
            wz.cmd_user_inspect(["--session", "s1"])
        self.assertEqual(cm.code, 3)


class RoleInspectGrading(unittest.TestCase):
    DELEGATOR = "arn:aws:iam::851725410668:role/prod-us100-AssumeRoleDelegator"
    TID = "6ca852a0-af83-4f2d-9da9-f2f3bd1d23a3"

    def _run(self, aws_proc, delegator=DELEGATOR, tid=TID):
        with mock.patch.object(wz, "_aws", return_value=aws_proc), \
             mock.patch.object(wz, "_wiz_delegator", return_value=(delegator, tid)), \
             exits() as cm:
            wz.cmd_role_inspect([])
        return cm.code

    def test_valid_trust_exit_0(self):
        role = {"Role": {"AssumeRolePolicyDocument": _trust(self.DELEGATOR, self.TID)}}
        self.assertEqual(self._run(_proc(0, json.dumps(role))), 0)

    def test_wrong_external_id_exit_1(self):
        role = {"Role": {"AssumeRolePolicyDocument": _trust(self.DELEGATOR, "WRONG-ID")}}
        self.assertEqual(self._run(_proc(0, json.dumps(role))), 1)

    def test_missing_role_exit_1(self):
        self.assertEqual(self._run(_proc(1, "", "NoSuchEntity: not found")), 1)

    def test_missing_creds_exit_3_not_1(self):
        # Anything but NoSuchEntity is environment: "no credentials" must never grade as
        # "learner wrong".
        self.assertEqual(self._run(_proc(255, "", "Unable to locate credentials")), 3)
        self.assertEqual(self._run(_proc(255, "", "ExpiredToken: token is expired")), 3)

    @staticmethod
    def _stmt(principal, external_id):
        return {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}}}

    def _multi(self, *statements):
        role = {"Role": {"AssumeRolePolicyDocument": {"Statement": list(statements)}}}
        return self._run(_proc(0, json.dumps(role)))

    def test_a_split_principal_and_external_id_do_not_combine(self):
        # AWS evaluates a statement as a unit: the delegator under a wrong external id, plus the right
        # external id for someone else, authorizes nobody — and used to grade 0.
        self.assertEqual(self._multi(self._stmt(self.DELEGATOR, "WRONG-ID"),
                                     self._stmt("arn:aws:iam::222222222222:role/Other", self.TID)), 1)

    def test_one_fully_correct_statement_among_others_is_valid(self):
        self.assertEqual(self._multi(self._stmt("arn:aws:iam::222222222222:role/Other", "OTHER-ID"),
                                     self._stmt(self.DELEGATOR, self.TID)), 0)

    def test_the_delegators_own_statement_must_carry_the_condition(self):
        unconditioned = {"Effect": "Allow", "Principal": {"AWS": self.DELEGATOR}, "Action": "sts:AssumeRole"}
        self.assertEqual(self._multi(unconditioned, self._stmt("arn:aws:iam::2:role/O", self.TID)), 1)


class Naming(unittest.TestCase):
    def test_stem_is_session_scoped(self):
        self.assertEqual(wz._lab_stem("abc123"), "lab-abc123")

    def test_session_id_from_flag_then_env(self):
        self.assertEqual(wz._session_id(["--session", "flagid"]), "flagid")
        with mock.patch.dict(wz.os.environ, {"INSTRUQT_SESSION_ID": "envid"}, clear=False):
            self.assertEqual(wz._session_id([]), "envid")

    def test_session_id_missing_is_invocation_error(self):
        with mock.patch.dict(wz.os.environ, {}, clear=True), exits() as cm:
            wz._session_id([])
        self.assertEqual(cm.code, 2)

    def test_user_email_keyed_on_session(self):
        self.assertEqual(wz._lab_user_email(["--session", "s1"])[0], "lab-s1@titra-labs.ai")


class ConnectorAndReaperSafety(unittest.TestCase):
    def _api(self, find_nodes, bytype_nodes=None):
        def side(query, variables):
            if query == wz.FIND:
                return {"connectors": {"nodes": find_nodes}}, "tid"
            if query == wz.BY_TYPE:
                return {"connectors": {"nodes": bytype_nodes or []}}, "tid"
            return {}, "tid"
        return side

    def test_find_connector_ranks_active_before_stale(self):
        nodes = [
            {"id": "e", "enabled": True, "status": "ERROR", "type": {"id": "aws"}, "config": {}},
            {"id": "c", "enabled": True, "status": "CONNECTED", "type": {"id": "aws"}, "config": {}},
        ]
        with mock.patch.object(wz, "api", side_effect=self._api(nodes)):
            self.assertEqual(wz.find_connector("111111111111")[0]["status"], "CONNECTED")

    def test_find_connector_by_type_fallback_when_no_parent(self):
        find = [{"id": "builtin", "type": {"id": "self-hosted"}, "config": {}}]  # no aws parent yet
        bytype = [{"id": "a", "enabled": True, "status": "CONNECTED", "type": {"id": "aws"},
                   "config": {"customerRoleARN": "arn:aws:iam::111111111111:role/WizAccess-Role"}}]
        with mock.patch.object(wz, "api", side_effect=self._api(find, bytype)):
            self.assertEqual([n["id"] for n in wz.find_connector("111111111111")], ["a"])

    HANDLER: typing.ClassVar = {"list": "reports", "filter": "search", "delete": "deleteReport",
                                "soft": False, "deleter": None}

    def test_reap_one_refuses_ambiguous_match(self):
        # Shared-tenant safety: >1 name match must skip, never delete — even with --commit.
        with mock.patch.object(wz, "_reap_handler", return_value=self.HANDLER), \
             mock.patch.object(wz, "_reap_find", return_value=(None, 2, None)):
            outcome, review = wz._reap_one("tok", "dc", "CreateServiceAccount", "lab-s1-sa", True)
        self.assertEqual(outcome, wz.FAILED)  # the resource is still there
        self.assertIn("matched 2", review)

    def test_reap_one_treats_an_already_gone_resource_as_absent(self):
        # The reap window overlaps by design, so a second pass over a reaped session finds the audit
        # Create with no resource behind it. That must not need review, and must not keep the user.
        with mock.patch.object(wz, "_reap_handler", return_value=self.HANDLER), \
             mock.patch.object(wz, "_reap_find", return_value=(None, 0, None)):
            self.assertEqual(wz._reap_one("tok", "dc", "CreateReport", "lab-s1-r", True), (wz.ABSENT, None))

    def test_an_unhandled_type_is_unknown_and_does_not_block(self):
        # Handler coverage is partial by construction: the generic plural+search handler misses most
        # create types, so blocking a miss would fail every reap and retain every user.
        with mock.patch.object(wz, "_reap_handler", return_value=self.HANDLER), \
             mock.patch.object(wz, "_reap_find", return_value=(None, None, "no such field")):
            outcome, review = wz._reap_one("tok", "dc", "CreateWidget", "lab-s1-w", True)
        self.assertEqual(outcome, wz.UNKNOWN)
        self.assertIn("no handler", review)
        self.assertNotIn(wz.UNKNOWN, wz._REAP_BLOCKING)

    def test_an_audit_entry_with_no_name_is_unknown(self):
        outcome, review = wz._reap_one("tok", "dc", "CreateWidget", None, True)
        self.assertEqual(outcome, wz.UNKNOWN)
        self.assertIn("no name in input", review)

    SA_HANDLER: typing.ClassVar = {"list": "serviceAccounts", "filter": "name", "soft": True,
                                   "delete": "deleteServiceAccount", "deleter": None}

    def test_a_cli_deployments_service_account_is_reaped_through_its_deployment(self):
        # deleteServiceAccount rejects an internal type:CLI account ("Internal service account cannot
        # be deleted"), so the uniform path is a permanent FAILED that retains the session's user.
        name = "lab-s1-cli-deployment-26dc83b5-503a-4725-a087-0764b1ef671d"
        sent = []

        def _gql(_tok, _dc, query, variables=None):
            sent.append(query)
            if "deployments" in query:
                return {"deployments": {"nodes": [{"id": "dep1", "name": "lab-s1-cli"}]}}, None
            return {}, None

        with mock.patch.object(wz, "_gql", side_effect=_gql), \
             mock.patch.object(wz, "_reap_find", return_value=(None, 0, None)):
            outcome, detail = wz._reap_service_account("tok", "dc", self.SA_HANDLER, "sa1", name)
        self.assertEqual((outcome, detail), (wz.REMOVED, None))
        self.assertTrue(any("deleteCliDeployment" in q for q in sent))
        self.assertFalse(any("deleteServiceAccount" in q for q in sent))

    def test_a_non_cli_service_account_still_takes_the_uniform_delete(self):
        # The sensor account comes from createServiceAccount and is deletable directly.
        with mock.patch.object(wz, "_reap_delete_uniform", return_value=(wz.REMOVED, None)) as uni:
            wz._reap_service_account("tok", "dc", self.SA_HANDLER, "sa1", "lab-s1-sensor")
        uni.assert_called_once()

    def test_a_cli_service_account_whose_deployment_is_gone_does_not_block(self):
        # Nothing left can delete the record, so blocking would retain the user with no pass able to
        # clear it.
        name = "lab-s1-cli-deployment-26dc83b5-503a-4725-a087-0764b1ef671d"
        with mock.patch.object(wz, "_gql", return_value=({"deployments": {"nodes": []}}, None)):
            outcome, detail = wz._reap_service_account("tok", "dc", self.SA_HANDLER, "sa1", name)
        self.assertEqual(outcome, wz.UNKNOWN)
        self.assertIn("lab-s1-cli", detail)
        self.assertNotIn(wz.UNKNOWN, wz._REAP_BLOCKING)

    def test_reap_enumeration_surfaces_graphql_errors(self):
        with mock.patch.object(wz, "_gql", return_value=({}, [{"message": "denied"}])):
            actions, alert = wz._reap_enumerate("tok", "dc", "lab-s1@example.com", 60)
        self.assertEqual(actions, [])
        self.assertIn("denied", alert)

    def _reap(self, outcome_or_actions, sweep=None):
        """cmd_reap over one audit outcome, with the sweep stubbed out. Returns the exit code."""
        one = (outcome_or_actions, "review") if isinstance(outcome_or_actions, str) else None
        actions = [("CreateWidget", "lab-s1-w")] if one else []
        with mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid")), \
             mock.patch.object(wz, "_reap_enumerate", return_value=(actions, None)), \
             mock.patch.object(wz, "_reap_one", return_value=one), \
             mock.patch.object(wz, "_reap_sweep_type", return_value=sweep or wz.Counter()), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
             exits() as cm:
            wz.cmd_reap(["--session", "s1", "--commit"])
        return cm.code

    def test_committed_reap_exits_3_when_enumeration_is_incomplete(self):
        with mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid")), \
             mock.patch.object(wz, "_reap_enumerate", return_value=([], "denied")), \
             mock.patch.object(wz, "_reap_sweep_type", return_value=wz.Counter()), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
             exits() as cm:
            wz.cmd_reap(["--session", "s1", "--commit"])
        self.assertEqual(cm.code, 3)

    def test_committed_reap_exits_3_when_a_sweep_lookup_fails(self):
        self.assertEqual(self._reap(None, sweep=wz.Counter({wz.FAILED: 1})), 3)

    def test_committed_reap_exits_0_when_coverage_is_unknown(self):
        # Residue we cannot act on is not cleanup that failed: exiting 3 here would make the reaper
        # retain every lab-<sid>@ user it was built to delete.
        self.assertEqual(self._reap(wz.UNKNOWN), 0)
        self.assertEqual(self._reap(wz.ABSENT), 0)
        self.assertEqual(self._reap(wz.REMOVED), 0)

    def test_a_deferred_resource_keeps_the_user_and_the_retry(self):
        # Exit 3 is the only signal the reaper acts on, and "come back to this" is exactly what a
        # multi-pass teardown needs — one extra daily cycle, then the record is gone.
        self.assertEqual(self._reap(wz.DEFERRED), 3)
        self.assertEqual(self._reap(wz.FAILED), 3)

    def test_reap_one_reports_failed_when_delete_does_not_remove_resource(self):
        found = [("id1", 1, None), ("id1", 1, None)]
        with mock.patch.object(wz, "_reap_handler", return_value=self.HANDLER), \
             mock.patch.object(wz, "_reap_find", side_effect=found), \
             mock.patch.object(wz, "_gql", return_value=({}, [{"message": "denied"}])):
            outcome, review = wz._reap_one("tok", "dc", "CreateReport", "lab-s1-report", True)
        self.assertEqual(outcome, wz.FAILED)
        self.assertIn("denied", review)

    def test_a_delete_id_is_a_variable_never_spliced_into_the_document(self):
        hostile = 'x" }) { _stub } } mutation { deleteTenant(input: { id: "y'
        sent = []

        def gql(tok, dc, query, variables=None):
            sent.append((query, variables))
            return {}, []

        with mock.patch.object(wz, "_gql", gql), \
             mock.patch.object(wz, "_reap_find", return_value=(None, 0, None)):
            outcome, _ = wz._reap_delete_uniform("tok", "dc", self.HANDLER, hostile, "lab-s1-report")
        self.assertEqual(outcome, wz.REMOVED)
        (query, variables), = sent
        self.assertIn(self.HANDLER["delete"], query)
        self.assertNotIn(hostile, query)
        self.assertEqual(variables, {"id": hostile})

    def test_committed_reap_counts_removals_the_sweep_could_not_have_named(self):
        actions = [("CreateReport", "lab-s1-r"), ("CreateReport", "Q3 report"), ("CreateReport", "old")]
        outcomes = [(wz.REMOVED, None), (wz.REMOVED, None), (wz.ABSENT, None)]
        err = io.StringIO()
        with mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid")), \
             mock.patch.object(wz, "_reap_enumerate", return_value=(actions, None)), \
             mock.patch.object(wz, "_reap_one", side_effect=outcomes), \
             mock.patch.object(wz, "_reap_sweep_type", return_value=wz.Counter({wz.REMOVED: 1})), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err), \
             exits() as cm:
            wz.cmd_reap(["--session", "s1", "--commit"])
        self.assertEqual(cm.code, 0)
        swept = len(wz._SWEEP_TYPES)
        self.assertIn(f"# {2 + swept} removed (1 audit-only), 1 absent", err.getvalue())

    def _outpost_reap(self, status, delete_err=None, status_err=None):
        """Drives the real _reap_outpost. Returns (outcome, detail, mutations issued)."""
        sent = []

        def gql(tok, dc, query, variables=None):
            if query is wz.OUTPOST_Q:
                if status_err:
                    return {}, [{"message": status_err}]
                return {"outpost": ({"id": "o1", "status": status} if status else None)}, []
            sent.append("delete" if query is wz.DELETE_OUTPOST else "uninstall")
            return {}, ([{"message": delete_err}] if delete_err else [])

        with mock.patch.object(wz, "_gql", gql):
            outcome, detail = wz._reap_outpost("tok", "dc", None, "o1", "lab-s1")
        return outcome, detail, sent

    def test_a_live_outpost_is_uninstalled_then_deferred_never_deleted(self):
        # deleteOutpost fails on a live record, so the sweep must not try it; the reaper also must not
        # sit in a poll loop inside a cron container.
        outcome, _detail, sent = self._outpost_reap("CONNECTED")
        self.assertEqual((outcome, sent), (wz.DEFERRED, ["uninstall"]))

    def test_an_uninstalling_outpost_is_deferred_without_a_second_uninstall(self):
        outcome, _detail, sent = self._outpost_reap("UNINSTALLING")
        self.assertEqual((outcome, sent), (wz.DEFERRED, []))

    def test_an_uninstalled_outpost_is_deleted(self):
        for status in wz._OUTPOST_DELETABLE:
            outcome, _detail, sent = self._outpost_reap(status)
            self.assertEqual((outcome, sent), (wz.REMOVED, ["delete"]), status)

    def test_an_absent_outpost_is_absent_not_failed(self):
        self.assertEqual(self._outpost_reap(None)[0], wz.ABSENT)

    def test_an_outpost_delete_that_errors_is_failed(self):
        self.assertEqual(self._outpost_reap("UNINSTALLED", delete_err="internal error")[0], wz.FAILED)

    def test_an_unreadable_outpost_status_is_failed_not_deferred(self):
        # A guaranteed type whose state we cannot read has not been proven clean.
        self.assertEqual(self._outpost_reap("CONNECTED", status_err="denied")[0], wz.FAILED)

    def test_the_sweep_routes_outpost_through_its_own_deleter(self):
        self.assertIn("Outpost", wz._SWEEP_TYPES)
        self.assertIs(wz._reap_handler("Outpost")["deleter"], wz._reap_outpost)
        self.assertIsNone(wz._reap_handler("Report")["deleter"])

    def test_kc_user_id_refuses_multiple_exact(self):
        dup = json.dumps([{"id": "1", "username": "lab-s1@titra-labs.ai"},
                          {"id": "2", "email": "lab-s1@titra-labs.ai"}])
        with mock.patch.object(wz, "_kc_call", return_value=(200, dup)), exits() as cm:
            wz._kc_user_id("http://kc", "realm", "tok", "lab-s1@titra-labs.ai")
        self.assertEqual(cm.code, 3)

    def test_kc_session_bundles_setup_in_field_order(self):
        # The three user verbs unpack this positionally, so field ORDER is the contract: a swap of
        # token/email would silently send the token as the lookup key.
        with mock.patch.object(wz, "_kc_env", return_value=("http://kc", "realm", "admin", "pw")), \
             mock.patch.object(wz, "_kc_token", return_value="tok"):
            s = wz._kc_session(["--session", "s1"])
        self.assertEqual((s.endpoint, s.realm, s.token), ("http://kc", "realm", "tok"))
        self.assertEqual((s.email, s.name), ("lab-s1@titra-labs.ai", "lab-s1"))
        self.assertEqual(tuple(s), ("http://kc", "realm", "tok", "lab-s1@titra-labs.ai", "lab-s1"))

    def test_wiz_type_rejects_non_identifier(self):
        with exits() as cm:
            wz.cmd_wiz_type(["--name", "Type; DROP"])
        self.assertEqual(cm.code, 2)


class Pagination(unittest.TestCase):
    """Every lookup that feeds a delete or an ==1 guard walks the whole connection, and a walk it cannot
    finish is a refusal, never "absent"."""

    @staticmethod
    def _pages(field, *pages, cursors=None):
        """An api() fake serving `pages` in order, keyed by the `after` variable it receives."""
        cursors = cursors or [f"c{i}" for i in range(len(pages))]
        by_after = {None: 0, **{cursors[i]: i + 1 for i in range(len(pages) - 1)}}
        seen = []

        def side(query, variables):
            seen.append(variables.get("after"))
            i = by_after[variables.get("after")]
            last = i == len(pages) - 1
            return {field: {"nodes": pages[i],
                            "pageInfo": {"hasNextPage": not last, "endCursor": None if last else cursors[i]}}}, "tid"
        side.seen = seen
        return side

    def test_an_exact_match_past_the_first_page_is_found(self):
        page1 = [{"id": str(i), "name": f"lab-s1-sensor-{i}"} for i in range(50)]
        side = self._pages("serviceAccounts", page1, [{"id": "sa", "name": "lab-s1-sensor"}])
        with mock.patch.object(wz, "api", side_effect=side):
            self.assertEqual(wz._find_sa("lab-s1-sensor")["id"], "sa")
        self.assertEqual(side.seen, [None, "c0"])

    def test_a_duplicate_past_the_first_page_is_deleted_by_ensure(self):
        # Before paging, `live[1:]` was computed on one page and a duplicate on the next survived.
        live = [{"id": "w1", "name": "lab-x", "enabled": True}], [{"id": "w2", "name": "lab-x", "enabled": False}]
        side = self._pages("automationWorkflows", *live)
        with mock.patch.object(wz, "api", side_effect=side):
            hits = wz._resolve_workflows("lab-x", exact=True)
        self.assertEqual([h["id"] for h in hits], ["w1", "w2"])

    def test_a_server_that_ignores_after_is_environment_3_not_absent(self):
        # Same page, same cursor, forever: without the guard the loop never ends or, capped, concludes
        # "absent" on a set it never finished reading.
        def side(query, variables):
            return {"cicdScanPolicies": {"nodes": [{"id": "p", "name": "other"}],
                                         "pageInfo": {"hasNextPage": True, "endCursor": "same"}}}, "tid"
        with mock.patch.object(wz, "api", side_effect=side), exits() as cm:
            wz._find_policy("fixture")
        self.assertEqual(cm.code, 3)

    def test_has_next_page_without_a_cursor_is_environment_3(self):
        def side(query, variables):
            return {"outposts": {"nodes": [], "pageInfo": {"hasNextPage": True, "endCursor": None}}}, "tid"
        with mock.patch.object(wz, "api", side_effect=side), exits() as cm:
            wz._resolve_outpost("lab-s1")
        self.assertEqual(cm.code, 3)

    def test_the_page_cap_is_a_refusal(self):
        def side(query, variables):
            n = int(variables.get("after") or 0)
            return {"sensors": {"nodes": [], "pageInfo": {"hasNextPage": True, "endCursor": str(n + 1)}}}, "tid"
        with mock.patch.object(wz, "api", side_effect=side) as api, exits() as cm:
            wz._resolve_sensor("lab-s1")
        self.assertEqual(cm.code, 3)
        self.assertEqual(api.call_count, wz._PAGE_CAP)

    def test_a_response_without_page_info_is_one_complete_page(self):
        with mock.patch.object(wz, "api", return_value=({"serviceAccounts": {"nodes": []}}, "tid")) as api:
            self.assertIsNone(wz._find_sa("lab-s1-sensor"))
        api.assert_called_once()

    # --- the reaper's list, through _gql (errors returned, never die)
    HANDLER: typing.ClassVar = {"list": "reports", "filter": "search", "delete": "deleteReport",
                                "soft": False, "deleter": None}

    def _gql_pages(self, *pages):
        side = self._pages("reports", *pages)
        return lambda tok, dc, q, v=None: (side(q, v or {})[0], []), side

    def test_the_sweep_walks_every_page_before_deleting(self):
        # The design review's F4 probe, inverted: 100 stem-named reports on page one and 3 on page two
        # are all swept, and the second request carries the first page's cursor.
        page1 = [{"id": str(i), "name": f"lab-s1-{i}"} for i in range(100)]
        page2 = [{"id": f"x{i}", "name": f"lab-s1-x{i}"} for i in range(3)]
        gql, side = self._gql_pages(page1, page2)
        with mock.patch.object(wz, "_gql", side_effect=gql), contextlib.redirect_stdout(io.StringIO()):
            tally = wz._reap_sweep_type("tok", "dc", "Report", "lab-s1", False)
        self.assertEqual(tally, wz.Counter({wz.REMOVED: 103}))
        self.assertEqual(side.seen, [None, "c0"])

    def test_a_sweep_that_cannot_finish_deletes_nothing_and_fails(self):
        def gql(tok, dc, q, v=None):
            if "mutation" in q:
                self.fail("a delete was issued from a partial list")
            return {"reports": {"nodes": [{"id": "r", "name": "lab-s1-r"}],
                                "pageInfo": {"hasNextPage": True, "endCursor": "same"}}}, []
        with mock.patch.object(wz, "_gql", side_effect=gql), contextlib.redirect_stdout(io.StringIO()):
            tally = wz._reap_sweep_type("tok", "dc", "Report", "lab-s1", True)
        self.assertEqual(tally, wz.Counter({wz.FAILED: 1}))

    def test_the_exact_one_guard_counts_across_pages(self):
        gql, _ = self._gql_pages([{"id": "a", "name": "lab-s1-r"}], [{"id": "b", "name": "lab-s1-r"}])
        with mock.patch.object(wz, "_gql", side_effect=gql):
            rid, count, err = wz._reap_find("tok", "dc", self.HANDLER, "lab-s1-r")
        self.assertEqual((rid, count, err), (None, 2, None))

    def test_audit_enumeration_stops_at_the_cap_with_an_alert(self):
        def gql(tok, dc, q, v=None):
            n = int((v or {}).get("after") or 0)
            return {"auditLogEntries": {"nodes": [], "pageInfo": {"hasNextPage": True, "endCursor": str(n + 1)}}}, []
        with mock.patch.object(wz, "_gql", side_effect=gql):
            actions, alert = wz._reap_enumerate("tok", "dc", "lab-s1@example.com", 60)
        self.assertEqual(actions, [])
        self.assertIn(f"more than {wz._PAGE_CAP} pages", alert)

    def test_audit_user_shares_the_fetcher_and_reports_an_incomplete_list_as_3(self):
        entry = {"action": "CreateReport", "actionType": "MUTATION", "status": "SUCCESS",
                 "timestamp": "t", "performer": {"id": "u", "name": "lab-s1@example.com"}}
        calls = []

        def side(query, variables):
            calls.append(variables.get("after"))
            return {"auditLogEntries": {"nodes": [entry],
                                        "pageInfo": {"hasNextPage": True, "endCursor": "same"}}}, "tid"
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(wz, "api", side_effect=side), contextlib.redirect_stdout(out), \
             contextlib.redirect_stderr(err), exits() as cm:
            wz.cmd_audit_user(["--match", "lab-s1"])
        self.assertEqual(cm.code, 3)
        self.assertEqual(calls, [None, "same"])
        self.assertIn("CreateReport", out.getvalue())
        self.assertIn("incomplete", err.getvalue())


class CloudSelection(unittest.TestCase):
    """The AWS-blindness this fixes failed in the worst direction: a live CONNECTED GCP connector
    graded as "no connector targets", telling a learner they hadn't done what they had just done."""
    GCP_NODE: typing.ClassVar = {"id": "g", "name": "lab-s1-connector", "enabled": True,
                                 "status": "CONNECTED", "type": {"id": "gcp"},
                                 "config": {"projectId": "wiz-lab-42"}}

    def test_default_is_aws_and_bad_value_is_invocation_error(self):
        self.assertEqual(wz._cloud([]), "aws")
        self.assertEqual(wz._cloud(["--cloud", "gcp"]), "gcp")
        with exits() as cm:
            wz._cloud(["--cloud", "oracle"])
        self.assertEqual(cm.code, 2)

    def test_gcp_connector_found_only_when_cloud_is_gcp(self):
        with mock.patch.object(wz, "api", return_value=({"connectors": {"nodes": [self.GCP_NODE]}}, "tid")):
            self.assertEqual([n["id"] for n in wz.find_connector("wiz-lab-42", "gcp")], ["g"])
            self.assertEqual(wz.find_connector("wiz-lab-42", "aws"), [])  # the old bug, locked down

    def test_gcp_inspect_healthy_exit_0(self):
        with mock.patch.object(wz, "find_connector", return_value=[self.GCP_NODE]), \
             exits() as cm:
            wz.cmd_connector_inspect(["--cloud", "gcp", "--account-id", "wiz-lab-42", "--require", "healthy"])
        self.assertEqual(cm.code, 0)

    def test_gcp_ensure_is_create_if_absent_never_patch(self):
        # No customerRoleARN equivalent to drift, so an existing connector is a no-op, not an update.
        with mock.patch.object(wz, "find_connector", return_value=[self.GCP_NODE]), \
             mock.patch.object(wz, "api") as api, exits() as cm:
            wz.cmd_connector_ensure(["--cloud", "gcp", "--account-id", "wiz-lab-42"])
        self.assertEqual(cm.code, 0)
        api.assert_not_called()

    def test_gcp_create_payload_is_managed_identity_with_empty_scopes(self):
        created = {"createConnector": {"connector": {"id": "n", "name": "lab-s1-connector", "status": "INITIAL"}}}
        with mock.patch.object(wz, "find_connector", return_value=[]), \
             mock.patch.object(wz, "api", return_value=(created, "tid")) as api, \
             exits() as cm:
            wz.cmd_connector_ensure(["--cloud", "gcp", "--account-id", "wiz-lab-42", "--session", "s1"])
        self.assertEqual(cm.code, 0)
        payload = api.call_args[0][1]["input"]
        self.assertEqual(payload["type"], "gcp")
        self.assertEqual(payload["authParams"], {"isManagedIdentity": True, "project_id": "wiz-lab-42"})
        self.assertTrue(all(v == [] for v in payload["extraConfig"].values()))
        self.assertNotIn("customerRoleARN", json.dumps(payload))

    def test_unsupported_paths_refuse_rather_than_guess(self):
        with exits() as cm:
            wz.cmd_connector_ensure(["--cloud", "azure", "--account-id", "sub-1"])
        self.assertEqual(cm.code, 2)
        with exits() as cm:  # provisioning belongs to terraform, not wizlab
            wz.cmd_role_ensure(["--cloud", "gcp"])
        self.assertEqual(cm.code, 2)


class TransientGraphqlErrors(unittest.TestCase):
    """Wiz returns a transient fault as a GraphQL error with HTTP 200, so _post's 5xx retry never sees
    it. Unretried, a read that 500s becomes "you didn't do the work" on a learner's screen."""

    def _post_returning(self, *responses):
        return mock.MagicMock(side_effect=list(responses))

    def test_transient_read_error_is_retried_then_succeeds(self):
        boom = {"errors": [{"message": "Internal server error"}], "data": None}
        ok = {"data": {"connectors": {"totalCount": 1}}}
        post = self._post_returning(boom, boom, ok)
        with mock.patch.object(wz, "token_and_dc", return_value=("t", "dc", "tid")), \
             mock.patch.object(wz, "_post", post), mock.patch.object(wz.time, "sleep"):
            data, _ = wz.api("query Q { connectors { totalCount } }", {})
        self.assertEqual(data["connectors"]["totalCount"], 1)
        self.assertEqual(post.call_count, 3)

    def test_a_mutation_is_never_retried(self):
        # It may have applied; retrying could create a second connector.
        boom = {"errors": [{"message": "Internal server error"}], "data": None}
        post = self._post_returning(boom, boom, boom)
        with mock.patch.object(wz, "token_and_dc", return_value=("t", "dc", "tid")), \
             mock.patch.object(wz, "_post", post), mock.patch.object(wz.time, "sleep"), \
             exits() as cm:
            wz.api("mutation M { createConnector { id } }", {})
        self.assertEqual(cm.code, 3)
        self.assertEqual(post.call_count, 1)

    def test_a_real_error_is_not_retried(self):
        bad = {"errors": [{"message": "Resource not found"}], "data": None}
        post = self._post_returning(bad, bad, bad)
        with mock.patch.object(wz, "token_and_dc", return_value=("t", "dc", "tid")), \
             mock.patch.object(wz, "_post", post), exits() as cm:
            wz.api("query Q { x }", {})
        self.assertEqual(cm.code, 3)
        self.assertEqual(post.call_count, 1)


class MutationSubmissionBudget(unittest.TestCase):
    """A mutation is SENT once. Wiz applies it before answering, so a 503, a timeout or an undecodable
    body leaves the outcome unknown, and a resend creates the second connector. Reads keep the retry.
    These drive the real transport — mocking `_post` away is what let the retry hide underneath it."""

    def setUp(self):
        self.enterContext(mock.patch.object(wz.time, "sleep"))
        self.enterContext(mock.patch.object(wz, "token_and_dc", return_value=("t", "dc", "tid")))

    def _sends(self, fn, *args, side_effect=None, body=None):
        """Returns (exit_code, submissions, message)."""
        if side_effect is None:
            cm = mock.MagicMock()
            cm.__enter__.return_value.read.return_value = body
            op = mock.MagicMock(return_value=cm)
        else:
            op = mock.MagicMock(side_effect=side_effect)
        err = io.StringIO()
        with mock.patch.object(wz.urllib.request, "urlopen", op), \
             contextlib.redirect_stderr(err), exits() as cm_exit:
            fn(*args)
        return cm_exit.code, op.call_count, err.getvalue()

    @staticmethod
    def _http(code):
        return urllib.error.HTTPError("https://x/", code, "boom", None, io.BytesIO(b"unavailable"))

    MUTATION = "mutation M { createConnector { id } }"

    def test_the_rule_is_a_property_of_the_document(self):
        self.assertEqual(wz._submissions("query Q { x }"), 3)
        self.assertEqual(wz._submissions("  { x }"), 3)  # anonymous query
        self.assertEqual(wz._submissions(self.MUTATION), 1)
        self.assertEqual(wz._submissions("subscription S { x }"), 1)  # unrecognised counts as unsafe

    def test_a_mutation_is_submitted_once_after_http_503(self):
        code, sends, msg = self._sends(wz.api, self.MUTATION, {}, side_effect=self._http(503))
        self.assertEqual((code, sends), (3, 1))
        self.assertIn("not resubmitted", msg)

    def test_a_mutation_is_submitted_once_after_a_timeout(self):
        code, sends, _ = self._sends(wz.api, self.MUTATION, {}, side_effect=TimeoutError("timed out"))
        self.assertEqual((code, sends), (3, 1))

    def test_a_mutation_is_submitted_once_when_the_response_will_not_decode(self):
        code, sends, _ = self._sends(wz.api, self.MUTATION, {}, body=b"<html>502 Bad Gateway</html>")
        self.assertEqual((code, sends), (3, 1))

    def test_a_read_still_resends_after_503(self):
        code, sends, _ = self._sends(wz.api, "query Q { connectors { id } }", {},
                                     side_effect=self._http(503))
        self.assertEqual((code, sends), (3, 3))

    def test_a_reap_delete_is_submitted_once(self):
        delete = 'mutation { deleteReport(input: { id: "r1" }) { _stub } }'
        code, sends, _ = self._sends(wz._gql, "tok", "dc", delete, side_effect=self._http(503))
        self.assertEqual((code, sends), (3, 1))

    def test_a_team_secret_mutation_is_submitted_once(self):
        upsert = "mutation($t: String!, $n: String!) { upsertTeamSecret(teamSlug: $t, name: $n) { name } }"
        with mock.patch.dict(wz.os.environ, {"INSTRUQT_API": "tok"}, clear=False):
            code, sends, _ = self._sends(wz._iq, upsert, {}, side_effect=self._http(503))
        self.assertEqual((code, sends), (3, 1))


class ConnectorLookupLayers(unittest.TestCase):
    """The account LINK lags create by 1-2 min, so the fallbacks decide what a check reports during
    the window a learner is most likely to click Check."""
    GCP: typing.ClassVar = {"id": "g", "name": "lab-s1-connector", "enabled": True,
                            "status": "CONNECTED", "type": {"id": "gcp"},
                            "config": {"projectId": "proj-1"}}

    def _api(self, find=None, search=None, bytype=None, total=0):
        def side(query, variables):
            if query == wz.FIND:
                return {"connectors": {"nodes": find or []}}, "tid"
            if query == wz.SEARCH:
                return {"connectors": {"nodes": search or [], "totalCount": len(search or [])}}, "tid"
            if query == wz.BY_TYPE:
                return {"connectors": {"nodes": bytype or [], "totalCount": total}}, "tid"
            return {}, "tid"
        return side

    def test_name_search_covers_the_pre_link_window(self):
        # Nothing linked yet, but the stem finds it — and BY_TYPE is never consulted.
        api = mock.MagicMock(side_effect=self._api(find=[], search=[self.GCP]))
        with mock.patch.object(wz, "api", api):
            self.assertEqual([n["id"] for n in wz.find_connector("proj-1", "gcp", "lab-s1")], ["g"])
        self.assertNotIn(wz.BY_TYPE, [c[0][0] for c in api.call_args_list])

    def test_search_result_must_still_target_the_account(self):
        # A same-stem connector for a DIFFERENT project is not this lab's connector.
        other = {**self.GCP, "config": {"projectId": "proj-2"}}
        with mock.patch.object(wz, "api", side_effect=self._api(search=[other], total=1)):
            self.assertEqual(wz.find_connector("proj-1", "gcp", "lab-s1"), [])

    def test_search_ignores_child_deployments(self):
        child = {"id": "c", "name": "GAR in lab-s1-connector", "enabled": True, "status": "CONNECTED",
                 "type": {"id": "gar"}, "config": {"projectId": "proj-1"}}
        with mock.patch.object(wz, "api", side_effect=self._api(search=[child, self.GCP])):
            self.assertEqual([n["id"] for n in wz.find_connector("proj-1", "gcp", "lab-s1")], ["g"])

    def test_beyond_the_page_is_environment_3_not_learner_1(self):
        # Past BY_TYPE_PAGE, "no match" stops meaning "absent". Reporting 1 would tell a learner they
        # did nothing; it would also let `ensure` create a duplicate of a connector it cannot see.
        with mock.patch.object(wz, "api", side_effect=self._api(total=wz.BY_TYPE_PAGE + 1)), \
             exits() as cm:
            wz.find_connector("proj-1", "gcp", None)
        self.assertEqual(cm.code, 3)

    def test_within_the_page_absence_is_still_learner_state(self):
        with mock.patch.object(wz, "api", side_effect=self._api(total=wz.BY_TYPE_PAGE)):
            self.assertEqual(wz.find_connector("proj-1", "gcp", None), [])

    def test_stem_is_optional_and_never_dies(self):
        with mock.patch.dict(wz.os.environ, {}, clear=True):
            self.assertIsNone(wz._stem_opt([]))
        self.assertEqual(wz._stem_opt(["--session", "s1"]), "lab-s1")


class AzureConnector(unittest.TestCase):
    SUB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_uppercased_subscription_id_is_normalised(self):
        # An uppercased GUID returns totalCount 0 from Wiz rather than an error, so a check would
        # grade a healthy subscription as empty. AWS digits and GCP project ids pass through.
        self.assertEqual(wz._norm_account(self.SUB.upper()), self.SUB)
        self.assertEqual(wz._norm_account("111111111111"), "111111111111")
        self.assertEqual(wz._norm_account("wiz-lab-42"), "wiz-lab-42")

    def test_ensure_needs_a_tenant_id(self):
        with mock.patch.dict(wz.os.environ, {}, clear=True), exits() as cm:
            wz.cmd_connector_ensure(["--cloud", "azure", "--account-id", self.SUB])
        self.assertEqual(cm.code, 2)

    def test_ensure_payload_is_managed_identity_with_subscription_and_tenant(self):
        created = {"createConnector": {"connector": {"id": "n", "name": "lab-s1-connector", "status": "INITIAL"}}}
        with mock.patch.object(wz, "find_connector", return_value=[]), \
             mock.patch.object(wz, "api", return_value=(created, "tid")) as api, \
             exits() as cm:
            wz.cmd_connector_ensure(["--cloud", "azure", "--account-id", self.SUB,
                                     "--tenant-id", "dir-1", "--session", "s1"])
        self.assertEqual(cm.code, 0)
        payload = api.call_args[0][1]["input"]
        self.assertEqual(payload["type"], "azure")
        self.assertEqual(payload["authParams"],
                         {"isManagedIdentity": True, "subscriptionId": self.SUB, "tenantId": "dir-1"})
        self.assertEqual(len(payload["extraConfig"]), 6)
        self.assertTrue(all(v == [] for v in payload["extraConfig"].values()))


class AzureRoleInspect(unittest.TestCase):
    SUB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    OID = "11111111-2222-3333-4444-555555555555"

    DEFAULT_ARGV: typing.ClassVar = ["--cloud", "azure", "--account-id", SUB, "--role-name", "WizCustomRole"]

    def _run(self, proc, argv=None, env=None):
        env = {"WIZ_TBCMP_AZURE_APP_OBJECT_ID": self.OID} if env is None else env
        with mock.patch.object(wz, "_az", return_value=proc) as az, \
             mock.patch.dict(wz.os.environ, env, clear=True), \
             exits() as cm:
            wz.cmd_role_inspect(argv if argv is not None else self.DEFAULT_ARGV)
        return cm.code, az

    def test_both_roles_assigned_exit_0(self):
        code, az = self._run(_proc(0, json.dumps(["Reader", "WizCustomRole"])))
        self.assertEqual(code, 0)
        # --fill-principal-name false is load-bearing: the default resolves names via Graph, which
        # Entra denies on this lease, so the call would fail for a non-learner reason.
        self.assertIn("--fill-principal-name", az.call_args[0])
        self.assertIn("false", az.call_args[0])

    def test_missing_role_name_flag_is_invocation_error(self):
        with mock.patch.dict(wz.os.environ, {"WIZ_TBCMP_AZURE_APP_OBJECT_ID": self.OID}, clear=True), \
             exits() as cm:
            wz.cmd_role_inspect(["--cloud", "azure", "--account-id", self.SUB])
        self.assertEqual(cm.code, 2)

    def test_missing_role_exit_1(self):
        self.assertEqual(self._run(_proc(0, json.dumps(["Reader"])))[0], 1)

    def test_session_scoped_custom_role_name(self):
        argv = ["--cloud", "azure", "--account-id", self.SUB, "--role-name", "lab-s1-WizCustomRole"]
        self.assertEqual(self._run(_proc(0, json.dumps(["Reader", "lab-s1-WizCustomRole"])), argv)[0], 0)
        self.assertEqual(self._run(_proc(0, json.dumps(["Reader", "WizCustomRole"])), argv)[0], 1)

    def test_az_failure_is_environment_3(self):
        self.assertEqual(self._run(_proc(1, "", "AuthorizationFailed"))[0], 3)

    def test_missing_operator_secret_is_environment_3(self):
        self.assertEqual(self._run(_proc(0, "[]"), env={})[0], 3)


class WizTenantFacts(unittest.TestCase):
    def _run(self, params, tid="tid-1"):
        with mock.patch.object(wz, "api", return_value=({"managedIdentityParameters": params}, tid)), \
             mock.patch.dict(wz.os.environ, {}, clear=True), \
             mock.patch.object(wz.sys, "stdout", io.StringIO()) as out, \
             exits() as cm:
            wz.cmd_wiz_tenant([])
        return cm.code, out.getvalue()

    def test_emits_gcp_service_account(self):
        code, text = self._run({"aws": {}, "gcp": {"serviceAccountEmail": "wizabc@prod-us100.iam.gserviceaccount.com"}})
        self.assertEqual(code, 0)
        self.assertIn("WIZ_GCP_SERVICE_ACCOUNT=wizabc@prod-us100.iam.gserviceaccount.com", text)

    def test_gcp_only_tenant_does_not_die_on_missing_aws_delegator(self):
        # The coupling this replaced would have failed a GCP lab for an absent AWS fact.
        code, text = self._run({"aws": {}, "gcp": {"serviceAccountEmail": "wizabc@prod-us100.iam.gserviceaccount.com"}})
        self.assertEqual(code, 0)
        self.assertNotIn("WIZ_REMOTE_ARN", text)  # empty facts are omitted, not emitted blank

    def test_no_facts_at_all_is_environment_3(self):
        # No aws delegator, no gcp SA AND no tid in the token — nothing a caller could consume.
        self.assertEqual(self._run({"aws": {}, "gcp": {}}, tid=None)[0], 3)


class SessionVerifyCsp(unittest.TestCase):
    def _mock_wiz(self):
        return mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid"))

    def _mock_api(self):
        return mock.patch.object(wz, "api", return_value=({"connectors": {"totalCount": 0}}, "tid"))

    def test_no_cloud_skips_csp_probe(self):
        with self._mock_wiz(), self._mock_api(), \
             mock.patch.object(wz, "_aws") as csp, \
             exits() as cm:
            wz.cmd_session_verify([])
        self.assertEqual(cm.code, 0)
        csp.assert_not_called()

    def test_unknown_cloud_is_invocation_error(self):
        with self._mock_wiz(), self._mock_api(), exits() as cm:
            wz.cmd_session_verify(["--cloud", "oracle"])
        self.assertEqual(cm.code, 2)

    def test_missing_csp_vars_exit_3(self):
        with self._mock_wiz(), self._mock_api(), \
             mock.patch.dict(wz.os.environ, {}, clear=True), \
             exits() as cm:
            wz.cmd_session_verify(["--cloud", "aws"])
        self.assertEqual(cm.code, 3)

    def test_csp_probe_failure_exit_3(self):
        env = {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y"}
        with self._mock_wiz(), self._mock_api(), \
             mock.patch.dict(wz.os.environ, env, clear=True), \
             mock.patch.object(wz, "_aws", return_value=_proc(1, "", "ExpiredToken")), \
             exits() as cm:
            wz.cmd_session_verify(["--cloud", "aws"])
        self.assertEqual(cm.code, 3)

    def test_csp_probe_success_exit_0(self):
        env = {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y"}
        with self._mock_wiz(), self._mock_api(), \
             mock.patch.dict(wz.os.environ, env, clear=True), \
             mock.patch.object(wz, "_aws", return_value=_proc(0, '{"Account": "123456789012"}')), \
             exits() as cm:
            wz.cmd_session_verify(["--cloud", "aws"])
        self.assertEqual(cm.code, 0)

    def _verify(self, cloud, env, proc, args=()):
        binary = {"aws": "_aws", "gcp": "_gcp", "azure": "_az"}[cloud]
        with self._mock_wiz(), self._mock_api(), \
             mock.patch.dict(wz.os.environ, env, clear=True), \
             mock.patch.object(wz, binary, return_value=proc), \
             contextlib.redirect_stdout(io.StringIO()), exits() as cm:
            wz.cmd_session_verify(["--cloud", cloud, *args])
        return cm.code

    GCP_ENV: typing.ClassVar = {"GOOGLE_CREDENTIALS": "{}", "GOOGLE_PROJECT": "wiz-lab-42"}
    AWS_ENV: typing.ClassVar = {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y"}

    def test_gcp_with_no_active_account_is_environment_3(self):
        # `gcloud auth list` exits 0 with `[]` when nothing activated, which used to pass verification
        # and left a terraform apply mid-lab to discover there are no credentials.
        self.assertEqual(self._verify("gcp", self.GCP_ENV, _proc(0, "[]")), 3)
        revoked = '[{"account": "a@b.iam.gserviceaccount.com", "status": ""}]'
        self.assertEqual(self._verify("gcp", self.GCP_ENV, _proc(0, revoked)), 3)

    def test_gcp_with_an_active_account_exits_0(self):
        active = '[{"account": "a@b.iam.gserviceaccount.com", "status": "ACTIVE"}]'
        self.assertEqual(self._verify("gcp", self.GCP_ENV, _proc(0, active)), 0)

    def test_unparseable_identity_is_environment_3(self):
        self.assertEqual(self._verify("gcp", self.GCP_ENV, _proc(0, "Updates are available")), 3)
        self.assertEqual(self._verify("aws", self.AWS_ENV, _proc(0, "")), 3)

    def test_aws_credentials_for_another_account_cannot_pass(self):
        proc = _proc(0, '{"Account": "999999999999"}')
        self.assertEqual(self._verify("aws", self.AWS_ENV, proc, ["--account-id", "123456789012"]), 3)
        self.assertEqual(self._verify("aws", self.AWS_ENV, proc, ["--account-id", "999999999999"]), 0)

    def test_azure_must_be_logged_in_to_the_declared_subscription(self):
        env = {"ARM_CLIENT_ID": "c", "ARM_CLIENT_SECRET": "s", "ARM_TENANT_ID": "t",
               "ARM_SUBSCRIPTION_ID": "5da4a5ee-0000-0000-0000-000000000001"}
        self.assertEqual(self._verify("azure", env, _proc(0, '{"id": "other-subscription"}')), 3)
        self.assertEqual(self._verify("azure", env, _proc(0, '{"id": "5DA4A5EE-0000-0000-0000-000000000001"}')), 0)


class GcpRoleInspect(unittest.TestCase):
    SA = "wizdeadbeef@prod-us100.iam.gserviceaccount.com"

    def _policy(self, roles, member=None):
        member = member or f"serviceAccount:{self.SA}"
        return json.dumps({"bindings": [{"role": r, "members": [member]} for r in roles]})

    def _run(self, proc, sa=SA):
        with mock.patch.object(wz, "_gcp", return_value=proc), \
             mock.patch.object(wz, "_wiz_gcp_sa", return_value=sa), \
             exits() as cm:
            wz.cmd_role_inspect(["--cloud", "gcp", "--account-id", "wiz-lab-42"])
        return cm.code

    def test_all_five_bound_exit_0(self):
        self.assertEqual(self._run(_proc(0, self._policy(wz.GCP_WIZ_ROLES))), 0)

    def test_one_missing_exit_1(self):
        self.assertEqual(self._run(_proc(0, self._policy(wz.GCP_WIZ_ROLES[:-1]))), 1)

    def test_bound_to_a_different_member_exit_1(self):
        other = self._policy(wz.GCP_WIZ_ROLES, member="user:someone@example.com")
        self.assertEqual(self._run(_proc(0, other)), 1)

    def test_gcloud_failure_is_environment_3(self):
        # No "not found" here means learner state: the project IS the lease, so any failure is env.
        self.assertEqual(self._run(_proc(1, "", "PERMISSION_DENIED")), 3)

    def test_empty_tenant_sa_is_environment_3(self):
        self.assertEqual(self._run(_proc(0, self._policy(wz.GCP_WIZ_ROLES)), sa=""), 3)


class SensorDetectionGrading(unittest.TestCase):
    ACTIVE: typing.ClassVar = [{"id": "s1", "name": "lab-x", "status": "ACTIVE", "type": "LINUX_VIRTUAL_MACHINE"}]

    def _api(self, sensor_nodes, det_count=0):
        def side(query, variables):
            if "sensors(" in query:
                return {"sensors": {"nodes": sensor_nodes, "totalCount": len(sensor_nodes)}}, "tid"
            if "detections(" in query:
                return {"detections": {"totalCount": det_count}}, "tid"
            return {}, "tid"
        return side

    def _exit(self, fn, argv, side):
        return exit_code(fn, argv, api=side)

    def test_sensor_inspect_exists(self):
        self.assertEqual(self._exit(wz.cmd_sensor_inspect, ["--name", "lab-x"], self._api(self.ACTIVE)), 0)

    def test_sensor_inspect_active_vs_inactive(self):
        self.assertEqual(
            self._exit(wz.cmd_sensor_inspect, ["--name", "lab-x", "--require", "active"], self._api(self.ACTIVE)), 0)
        inactive = [{"id": "s1", "name": "lab-x", "status": "INACTIVE", "type": "x"}]
        self.assertEqual(
            self._exit(wz.cmd_sensor_inspect, ["--name", "lab-x", "--require", "active"], self._api(inactive)), 1)

    def test_sensor_inspect_absent_exit_1(self):
        self.assertEqual(self._exit(wz.cmd_sensor_inspect, ["--name", "lab-x"], self._api([])), 1)

    def test_sensor_inspect_bad_require_exit_2(self):
        self.assertEqual(
            self._exit(wz.cmd_sensor_inspect, ["--name", "lab-x", "--require", "bogus"], self._api(self.ACTIVE)), 2)

    def test_sensor_name_matches_exactly_not_substring(self):
        # `search` is substring server-side, so a longer name that merely contains the stem must NOT
        # match — else a neighbour session's sensor grades this one.
        other = [{"id": "s2", "name": "lab-xyz", "status": "ACTIVE", "type": "x"}]
        self.assertEqual(self._exit(wz.cmd_sensor_inspect, ["--name", "lab-x"], self._api(other)), 1)

    def test_detection_hit_exit_0(self):
        self.assertEqual(
            self._exit(wz.cmd_detection_inspect, ["--name", "lab-x", "--rule-name", "R"], self._api(self.ACTIVE, 3)), 0)

    def test_detection_none_exit_1(self):
        self.assertEqual(
            self._exit(wz.cmd_detection_inspect, ["--name", "lab-x", "--rule-name", "R"], self._api(self.ACTIVE, 0)), 1)

    def test_detection_no_sensor_exit_1(self):
        self.assertEqual(
            self._exit(wz.cmd_detection_inspect, ["--name", "lab-x", "--rule-name", "R"], self._api([])), 1)

    def test_detection_missing_rule_exit_2(self):
        self.assertEqual(
            self._exit(wz.cmd_detection_inspect, ["--name", "lab-x"], self._api(self.ACTIVE)), 2)


class WorkflowGrading(unittest.TestCase):
    """Locks two things a live tenant proved and a reader would otherwise get wrong: `enabled` is the
    only publish signal (activeVersion/draftVersion/versions read null/0 on every workflow), and the
    graded branch comes from a run's outboundEdge on a SWITCH_CASE step, not from the definition."""

    LIVE: typing.ClassVar = [{"id": "w1", "name": "lab-x-night-watch", "enabled": True,
                              "project": {"name": "p"},
                              "steps": [{"id": "s1", "name": "Route", "type": "SWITCH_CASE"}]}]

    def _api(self, wf_nodes, run_nodes=()):
        def side(query, variables):
            if "automationWorkflowRuns(" in query:
                return {"automationWorkflowRuns": {"nodes": list(run_nodes)}}, "tid"
            if "automationWorkflows(" in query:
                return {"automationWorkflows": {"nodes": wf_nodes}}, "tid"
            return {}, "tid"
        return side

    def _run(self, edge, stype="SWITCH_CASE"):
        return {"id": "r1", "status": "COMPLETED",
                "steps": [{"status": "COMPLETED", "outboundEdge": edge,
                           "step": {"name": "Route", "type": stype}}]}

    def _exit(self, fn, argv, side):
        return exit_code(fn, argv, api=side)

    def test_inspect_exists_and_absent(self):
        self.assertEqual(self._exit(wz.cmd_workflow_inspect, ["--name", "lab-x"], self._api(self.LIVE)), 0)
        self.assertEqual(self._exit(wz.cmd_workflow_inspect, ["--name", "lab-x"], self._api([])), 1)

    def test_published_is_enabled_only(self):
        argv = ["--name", "lab-x", "--require", "published"]
        self.assertEqual(self._exit(wz.cmd_workflow_inspect, argv, self._api(self.LIVE)), 0)
        saved = [dict(self.LIVE[0], enabled=False)]
        self.assertEqual(self._exit(wz.cmd_workflow_inspect, argv, self._api(saved)), 1)

    def test_inspect_bad_require_exit_2(self):
        self.assertEqual(
            self._exit(wz.cmd_workflow_inspect, ["--name", "lab-x", "--require", "branched"],
                       self._api(self.LIVE)), 2)

    def test_stem_matches_by_prefix_but_exact_name_pins(self):
        # The guide tells a learner to type lab-<sid>-night-watch, so the stem must match a suffixed
        # name. --exact-name is for a caller that knows the whole thing.
        self.assertEqual(self._exit(wz.cmd_workflow_inspect, ["--name", "lab-x"], self._api(self.LIVE)), 0)
        self.assertEqual(
            self._exit(wz.cmd_workflow_inspect, ["--name", "lab-x", "--exact-name"], self._api(self.LIVE)), 1)

    def test_enabled_outranks_disabled_leftover_on_same_stem(self):
        nodes = [dict(self.LIVE[0], id="old", enabled=False), self.LIVE[0]]
        self.assertEqual(
            self._exit(wz.cmd_workflow_inspect, ["--name", "lab-x", "--require", "published"],
                       self._api(nodes)), 0)

    def test_run_branch_grades_the_edge_taken(self):
        argv = ["--name", "lab-x", "--require", "branch", "--branch", "Malicious"]
        self.assertEqual(
            self._exit(wz.cmd_workflowrun_inspect, argv, self._api(self.LIVE, [self._run("Malicious")])), 0)
        self.assertEqual(
            self._exit(wz.cmd_workflowrun_inspect, argv, self._api(self.LIVE, [self._run("default")])), 1)

    def test_run_branch_grades_every_step_type(self):
        # A CONDITION leaves by true/false and an unbranched step by main; a verb that read only
        # SWITCH_CASE edges printed "none" on a run that demonstrably took the false edge.
        argv = ["--name", "lab-x", "--require", "branch", "--branch", "false"]
        self.assertEqual(
            self._exit(wz.cmd_workflowrun_inspect, argv, self._api(self.LIVE, [self._run("false", "CONDITION")])), 0)
        self.assertEqual(
            self._exit(wz.cmd_workflowrun_inspect, argv, self._api(self.LIVE, [self._run("true", "CONDITION")])), 1)

    def _failed_step_run(self, edge="error", status="FAILED"):
        return {"id": "r2", "status": "COMPLETED",
                "steps": [{"status": status, "outboundEdge": edge, "step": {"name": "Look up team", "type": "ECHO"}},
                          {"status": "COMPLETED", "outboundEdge": "main", "step": {"name": "Alert", "type": "ECHO"}}]}

    def test_run_error_path_needs_a_failed_step_inside_a_completed_run(self):
        # Every failed step reads outboundEdge "error", edge or no edge; the run filter admits COMPLETED
        # runs only, so FAILED-step-in-COMPLETED-run is what proves the edge was followed.
        argv = ["--name", "lab-x", "--require", "error-path"]
        self.assertEqual(
            self._exit(wz.cmd_workflowrun_inspect, argv, self._api(self.LIVE, [self._failed_step_run()])), 0)
        self.assertEqual(
            self._exit(wz.cmd_workflowrun_inspect, argv, self._api(self.LIVE, [self._run("main", "ECHO")])), 1)
        self.assertEqual(
            self._exit(wz.cmd_workflowrun_inspect, argv,
                       self._api(self.LIVE, [self._failed_step_run(status="COMPLETED")])), 1)
        self.assertEqual(self._exit(wz.cmd_workflowrun_inspect, argv, self._api(self.LIVE, [])), 1)

    def test_run_wait_dies_on_the_enum_spelling_of_canceled(self):
        # CANCELLED would never match, so a cancelled run would poll to the deadline instead of exiting 3
        # on the first read.
        side = self._api(self.LIVE, [{"id": "r1", "status": "CANCELED", "steps": []}])
        with mock.patch.object(wz, "api", side_effect=side), mock.patch.object(wz.time, "sleep") as slept, \
                exits() as cm:
            wz._wait_for_run("r1", timeout=60, interval=2)
        self.assertEqual(cm.code, 3)
        slept.assert_not_called()

    def test_run_completed_and_none(self):
        argv = ["--name", "lab-x", "--require", "completed"]
        self.assertEqual(self._exit(wz.cmd_workflowrun_inspect, argv, self._api(self.LIVE, [self._run("x")])), 0)
        self.assertEqual(self._exit(wz.cmd_workflowrun_inspect, argv, self._api(self.LIVE, [])), 1)

    def test_run_absent_workflow_exit_1(self):
        self.assertEqual(self._exit(wz.cmd_workflowrun_inspect, ["--name", "lab-x"], self._api([])), 1)

    def test_run_branch_without_branch_flag_exit_2(self):
        self.assertEqual(
            self._exit(wz.cmd_workflowrun_inspect, ["--name", "lab-x", "--require", "branch"],
                       self._api(self.LIVE)), 2)

    def test_ensure_needs_a_readable_definition(self):
        self.assertEqual(self._exit(wz.cmd_workflow_ensure, ["--name", "lab-x"], self._api(self.LIVE)), 2)
        self.assertEqual(
            self._exit(wz.cmd_workflow_ensure, ["--name", "lab-x", "--definition", "/nope.json"],
                       self._api(self.LIVE)), 2)

    def test_run_ensure_rejects_unknown_initial_step(self):
        argv = ["--name", "lab-x", "--initial-step", "Nope", "--data", "/nope.json"]
        self.assertEqual(self._exit(wz.cmd_workflowrun_ensure, argv, self._api(self.LIVE)), 2)

    def _api_validate(self, issues, wf_nodes=None):
        nodes = self.LIVE if wf_nodes is None else wf_nodes

        def side(query, variables):
            if "validateAutomationWorkflow" in query:
                return {"validateAutomationWorkflow": {"issues": issues}}, "tid"
            if "automationWorkflows(" in query:
                return {"automationWorkflows": {"nodes": nodes}}, "tid"
            if "createAutomationWorkflow" in query:
                return {"createAutomationWorkflow": {"workflow": {"id": "w1", "name": "lab-x-night-watch",
                                                                  "enabled": True}}}, "tid"
            return {}, "tid"
        return side

    def _definition_file(self):
        d = tempfile.mkdtemp()
        path = pathlib.Path(d) / "wf.json"
        path.write_text(json.dumps({"steps": [], "triggers": []}))
        self.addCleanup(shutil.rmtree, d)
        return str(path)

    def test_ensure_refuses_to_submit_an_invalid_definition(self):
        # An invalid definition is the caller's bug, not the environment's: exit 2, and the create is
        # never sent — the API's own refusal names neither the step nor the field.
        argv = ["--name", "lab-x", "--definition", self._definition_file()]
        issues = [{"target": {"stepId": "route"}, "message": "field 'name' does not exist in expression"}]
        self.assertEqual(self._exit(wz.cmd_workflow_ensure, argv, self._api_validate(issues)), 2)

    def test_dry_run_reports_issues_without_mutating(self):
        argv = ["--name", "lab-x", "--definition", self._definition_file(), "--dry-run"]
        issues = [{"target": {"triggerId": "eventThreats"}, "message": "outbound edge references non-existent step"}]
        self.assertEqual(self._exit(wz.cmd_workflow_ensure, argv, self._api_validate(issues)), 1)
        self.assertEqual(self._exit(wz.cmd_workflow_ensure, argv, self._api_validate([])), 0)

    def test_issue_line_survives_a_workflow_level_target(self):
        # The workflow member of the target union carries only `_stub`, so nothing names a step.
        self.assertEqual(wz._issue_line({"target": {"_stub": None}, "message": "m"}), "workflow: m")
        self.assertEqual(wz._issue_line({"message": "m"}), "workflow: m")

    def _ensure_queries(self, wf_nodes):
        seen = []

        def side(query, variables):
            seen.append(query)
            return self._api_validate([], wf_nodes=wf_nodes)(query, variables)
        argv = ["--name", "lab-x", "--definition", self._definition_file()]
        with mock.patch.object(wz, "api", side_effect=side), exits():
            wz.cmd_workflow_ensure(argv)
        return seen

    def test_ensure_sends_no_version_bearing_mutation(self):
        # The version refusal (SPEC.md) covers EVERY version-bearing path: the first fix removed the
        # publish call and left updateAutomationWorkflowDraft, so the same defect failed a second play.
        # This asserts the class, not the one call.
        for nodes in ([], self.LIVE):
            seen = self._ensure_queries(nodes)
            for banned in ("publishAutomationWorkflowVersion", "updateAutomationWorkflowDraft",
                           "revertAutomationWorkflowToVersion", "automationWorkflowVersion("):
                self.assertFalse([q for q in seen if banned in q], f"{banned} sent with nodes={bool(nodes)}")

    def test_ensure_patches_a_live_workflow_and_keeps_its_id(self):
        # A rebuild drops the test runs earlier activities graded; the patch keeps the workflow id, and
        # the patch type has no projectId key.
        sent = {}

        def side(query, variables):
            if "updateAutomationWorkflow(" in query:
                sent.update(variables["input"])
                return {"updateAutomationWorkflow": {"workflow": {"id": "w1", "name": "lab-x", "enabled": True}}}, "tid"
            return self._api_validate([], wf_nodes=self.LIVE)(query, variables)
        argv = ["--name", "lab-x", "--definition", self._definition_file(), "--project-id", "p1"]
        self.assertEqual(self._exit(wz.cmd_workflow_ensure, argv, side), 0)
        self.assertEqual(sent["id"], "w1")
        self.assertNotIn("projectId", sent["patchStrict"])
        self.assertTrue(sent["patchStrict"]["enabled"])

    def test_ensure_creates_when_absent_and_deletes_only_a_duplicate(self):
        def names(seen):
            return [q.split("(")[0].split()[-1] for q in seen if "mutation" in q]
        self.assertEqual(names(self._ensure_queries([])), ["CreateWorkflow"])
        self.assertEqual(names(self._ensure_queries(self.LIVE)), ["UpdateWorkflow"])
        dup = [*self.LIVE, {**self.LIVE[0], "id": "w2"}]
        self.assertEqual(names(self._ensure_queries(dup)), ["DeleteWorkflow", "UpdateWorkflow"])

    def test_run_inspect_spans_every_workflow_on_the_stem(self):
        # Two attempts on one stem: the edge lives on the second, and grading only the first would fail a
        # learner who got there.
        two = [dict(self.LIVE[0], id="w1", name="lab-x-night-watch"),
               dict(self.LIVE[0], id="w2", name="lab-x-night-watch-2")]
        captured = {}

        def side(query, variables):
            if "automationWorkflowRuns(" in query:
                captured["ids"] = variables["f"]["workflowId"]["equals"]
                return {"automationWorkflowRuns": {"nodes": [self._run("Malicious")]}}, "tid"
            return {"automationWorkflows": {"nodes": two}}, "tid"
        argv = ["--name", "lab-x", "--require", "branch", "--branch", "Malicious"]
        self.assertEqual(self._exit(wz.cmd_workflowrun_inspect, argv, side), 0)
        self.assertEqual(sorted(captured["ids"]), ["w1", "w2"])


class OutpostGrading(unittest.TestCase):
    """Locks the OutpostStatus grading table and the uninstall->wait->delete order. A refactor that
    reorders the reap would silently leave an Outpost record behind, which no lab check would
    catch."""

    def _api(self, status, after=None, scans=None):
        """after: statuses `outpost(id)` returns on successive polls, for the uninstall wait.
        scans: one (successful, failed) pair per daily bucket the scan-metrics trend reports."""
        seq, calls = list(after or []), []

        def side(query, variables):
            calls.append((query, variables))
            if "resourceScanMetricsTrend" in query:
                pts = [{"timestamp": f"d{i}",
                        "aggregatedMetrics": {"totalScansCount": s + f, "successfulScansCount": s,
                                              "failedScansCount": f}}
                       for i, (s, f) in enumerate(scans or [])]
                return {"resourceScanMetricsTrend": {"dataPoints": pts}}, "tid"
            if "outposts(" in query:
                nodes = [] if status is None else [{"id": "o1", "name": "lab-x", "status": status}]
                return {"outposts": {"nodes": nodes, "totalCount": len(nodes)}}, "tid"
            if "outpost(id:" in query:
                st = seq.pop(0) if seq else status
                return {"outpost": None if st == "GONE" else {"id": "o1", "status": st}}, "tid"
            if "createOutpost" in query:
                return {"createOutpost": {"outpost": {"id": "o1", "name": "lab-x", "status": "INITIALIZING"}}}, "tid"
            return {}, "tid"
        return side, calls

    def _exit(self, fn, argv, side):
        # A fake clock, not just a no-op sleep: the uninstall wait is bounded by time.monotonic(), so a
        # patched-out sleep alone would spin on the real clock for the whole --timeout.
        clock = {"t": 1000.0}
        with mock.patch.object(wz, "api", side_effect=side), \
                mock.patch.object(wz.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s)), \
                mock.patch.object(wz.time, "monotonic", lambda: clock["t"]), \
                exits() as cm:
            fn(argv)
        return cm.code

    def test_inspect_grades_the_enum_not_the_ui_word(self):
        for status, require, want in [
            ("CONNECTED", "connected", 0),
            ("CONNECTED", "initialized", 0),      # CONNECTED is a superset of INITIALIZED
            ("INITIALIZED", "connected", 1),
            ("INITIALIZED", "initialized", 0),
            ("INITIALIZING", "initialized", 1),   # a fresh createOutpost lands here
            ("UNINSTALLED", "initialized", 1),
            ("UNINSTALLED", "exists", 0),
            ("ERROR", "connected", 1),
        ]:
            side, _ = self._api(status)
            self.assertEqual(
                self._exit(wz.cmd_outpost_inspect, ["--name", "lab-x", "--require", require], side), want,
                f"{status} --require {require}")

    def test_inspect_absent_exit_1(self):
        side, _ = self._api(None)
        self.assertEqual(self._exit(wz.cmd_outpost_inspect, ["--name", "lab-x"], side), 1)

    def test_scanned_needs_a_successful_scan_not_just_connected(self):
        # A CONNECTED Outpost commonly has scanned nothing, so CONNECTED must not satisfy --require
        # scanned. Failed-only is also not satisfied (it means the node pool cannot snapshot), and
        # the daily buckets are summed across the window.
        for scans, want in [([], 1), ([(0, 0), (0, 0)], 1), ([(0, 3)], 1), ([(0, 0), (1, 0)], 0),
                            ([(5, 2)], 0)]:
            side, _ = self._api("CONNECTED", scans=scans)
            self.assertEqual(
                self._exit(wz.cmd_outpost_inspect, ["--name", "lab-x", "--require", "scanned"], side),
                want, f"scans={scans}")

    def test_scanned_absent_outpost_never_queries_metrics(self):
        side, calls = self._api(None, scans=[(9, 0)])
        self.assertEqual(
            self._exit(wz.cmd_outpost_inspect, ["--name", "lab-x", "--require", "scanned"], side), 1)
        self.assertFalse([c for c in calls if "resourceScanMetricsTrend" in c[0]])

    def test_inspect_bad_require_exit_2(self):
        side, _ = self._api("CONNECTED")
        self.assertEqual(
            self._exit(wz.cmd_outpost_inspect, ["--name", "lab-x", "--require", "bogus"], side), 2)

    def test_inspect_name_matches_exactly_not_substring(self):
        # `search` is substring server-side; a neighbour session's longer name must not grade this one.
        def side(query, variables):
            return {"outposts": {"nodes": [{"id": "o2", "name": "lab-xyz", "status": "CONNECTED"}]}}, "tid"
        self.assertEqual(self._exit(wz.cmd_outpost_inspect, ["--name", "lab-x"], side), 1)

    def test_ensure_needs_role_arn(self):
        side, _ = self._api(None)
        self.assertEqual(self._exit(wz.cmd_outpost_ensure, ["--name", "lab-x"], side), 2)

    def test_ensure_is_idempotent_by_name_and_never_recreates(self):
        side, calls = self._api("CONNECTED")
        self.assertEqual(self._exit(wz.cmd_outpost_ensure, ["--name", "lab-x", "--role-arn", "a"], side), 0)
        self.assertNotIn("createOutpost", " ".join(q for q, _ in calls))

    def test_ensure_posts_role_arn_inside_aws_config(self):
        side, calls = self._api(None)
        self.assertEqual(self._exit(wz.cmd_outpost_ensure, ["--name", "lab-x", "--role-arn", "arn:r"], side), 0)
        inp = next(v["input"] for q, v in calls if "createOutpost" in q)
        self.assertEqual(inp["awsConfig"]["roleARN"], "arn:r")   # caps, nested — the capture's shape
        self.assertEqual(inp["allowedRegions"], ["us-east-1"])

    def test_delete_uninstalls_first_then_waits_then_deletes(self):
        side, calls = self._api("INITIALIZED", after=["UNINSTALLING", "UNINSTALLED"])
        self.assertEqual(self._exit(wz.cmd_outpost_delete, ["--name", "lab-x"], side), 0)
        order = [q.split("(")[0].split()[-1] for q, _ in calls if "mutation" in q]
        self.assertEqual(order, ["UninstallOutpost", "DeleteOutpost"])

    def test_delete_never_deletes_a_live_outpost_directly(self):
        # deleteOutpost on a live Outpost is a server-side internal error, so it must not be attempted.
        side, calls = self._api("CONNECTED", after=["UNINSTALLED"])
        self._exit(wz.cmd_outpost_delete, ["--name", "lab-x"], side)
        first = next(q for q, _ in calls if "mutation" in q)
        self.assertIn("UninstallOutpost", first)

    def test_delete_skips_uninstall_when_already_uninstalled(self):
        side, calls = self._api("UNINSTALLED")
        self.assertEqual(self._exit(wz.cmd_outpost_delete, ["--name", "lab-x"], side), 0)
        self.assertNotIn("uninstallOutpost", " ".join(q for q, _ in calls))

    def test_delete_absent_is_exit_0(self):
        side, _ = self._api(None)
        self.assertEqual(self._exit(wz.cmd_outpost_delete, ["--name", "lab-x"], side), 0)

    def test_delete_exits_0_when_uninstall_outlives_the_wait(self):
        # Best-effort: the EKS infra dies with the lease, so a stuck record must not fail the reaper.
        side, calls = self._api("INITIALIZED", after=["UNINSTALLING"] * 40)
        self.assertEqual(self._exit(wz.cmd_outpost_delete, ["--name", "lab-x", "--timeout", "60"], side), 0)
        self.assertNotIn("deleteOutpost", " ".join(q for q, _ in calls))


class OutpostConnectorBinding(unittest.TestCase):
    """Locks phase 2 of the Outpost deploy. The failure it guards has no lifecycle signal at all: a
    connector with no `outpost` still reaches CONNECTED, and its Outpost holds INITIALIZED with
    clusters null and errorCode null, so every status a check could read says success."""

    def _node(self, outpost=None):
        return {"id": "c1", "name": "lab-x-connector", "enabled": True, "status": "CONNECTED",
                "type": {"id": "aws"}, "outpost": outpost,
                "config": {"customerRoleARN": "arn:aws:iam::111111111111:role/WizAccess-Role"}}

    def _exit(self, fn, argv, node=None, outposts=None, api=None):
        return exit_code(fn, argv, find_connector=[node] if node else [], _resolve_outpost=outposts,
                         api=api or (lambda q, v: ({}, "tid")))

    # --session, because resolving "which Outpost should this be bound to" goes through the same
    # session stem the Outpost was named on.
    ARGS: typing.ClassVar = ["--account-id", "111111111111", "--require", "outpost-bound",
                             "--session", "x"]

    def test_unbound_connector_fails_despite_being_connected(self):
        self.assertEqual(self._exit(wz.cmd_connector_inspect, self.ARGS, self._node(None),
                                    {"id": "o1"}), 1)

    def test_bound_to_someone_elses_outpost_fails(self):
        # Two concurrent leases in one tenant: binding the neighbour's Outpost builds their cluster.
        self.assertEqual(self._exit(wz.cmd_connector_inspect, self.ARGS,
                                    self._node({"id": "o2", "name": "lab-y"}), {"id": "o1"}), 1)

    def test_bound_to_the_session_outpost_passes(self):
        self.assertEqual(self._exit(wz.cmd_connector_inspect, self.ARGS,
                                    self._node({"id": "o1", "name": "lab-x"}), {"id": "o1"}), 0)

    def test_explicit_outpost_id_needs_no_name_lookup(self):
        with mock.patch.object(wz, "_resolve_outpost") as resolve:
            self.assertEqual(self._exit(wz.cmd_connector_inspect,
                                        [*self.ARGS, "--outpost-id", "o1"],
                                        self._node({"id": "o1", "name": "lab-x"})), 0)
        resolve.assert_not_called()

    def test_no_outpost_at_all_is_exit_1_not_an_error(self):
        # The learner skipped phase 1: a check, so 1 — never 2/3, which a lab would have to remap.
        self.assertEqual(self._exit(wz.cmd_connector_inspect, self.ARGS, self._node(None), None), 1)

    def test_absent_connector_is_exit_1(self):
        self.assertEqual(self._exit(wz.cmd_connector_inspect, self.ARGS, None, {"id": "o1"}), 1)

    def test_bad_require_is_exit_2(self):
        self.assertEqual(self._exit(wz.cmd_connector_inspect,
                                    ["--account-id", "111111111111", "--require", "bogus"]), 2)

    def test_outpost_id_without_scanner_role_is_exit_2(self):
        # Bound with no scanner role the connector converges and never scans a disk, so refuse to
        # create one rather than ship a lab that grades CONNECTED and scans nothing.
        self.assertEqual(self._exit(wz.cmd_connector_ensure,
                                    ["--account-id", "111111111111", "--outpost-id", "o1"]), 2)

    def test_scanner_role_without_outpost_id_is_exit_2(self):
        self.assertEqual(self._exit(wz.cmd_connector_ensure,
                                    ["--account-id", "111111111111", "--scanner-role-arn", "arn:s"]), 2)

    def test_create_payload_carries_all_three_auth_params(self):
        created = {"createConnector": {"connector": {"id": "c1", "name": "lab-x-connector",
                                                     "status": "INITIAL"}}}
        calls = []

        def api(query, variables):
            calls.append((query, variables))
            return created, "tid"
        self.assertEqual(self._exit(wz.cmd_connector_ensure,
                                    ["--account-id", "111111111111", "--session", "x",
                                     "--role-arn", "arn:r", "--outpost-id", "o1",
                                     "--scanner-role-arn", "arn:s"], api=api), 0)
        auth = calls[0][1]["input"]["authParams"]
        self.assertEqual(auth, {"customerRoleARN": "arn:r", "outpostId": "o1",
                                "diskAnalyzer": {"scanner": {"roleARN": "arn:s"}}})

    def test_ensure_binds_by_name_the_way_the_console_dropdown_does(self):
        created = {"createConnector": {"connector": {"id": "c1", "name": "lab-x-connector",
                                                     "status": "INITIAL"}}}
        calls = []

        def api(query, variables):
            calls.append((query, variables))
            return created, "tid"
        self.assertEqual(self._exit(wz.cmd_connector_ensure,
                                    ["--account-id", "111111111111", "--session", "x",
                                     "--outpost-name", "lab-x", "--scanner-role-arn", "arn:s"],
                                    outposts={"id": "o1"}, api=api), 0)
        self.assertEqual(calls[0][1]["input"]["authParams"]["outpostId"], "o1")

    def test_ensure_refuses_to_create_an_unbindable_connector(self):
        # Phase 1 never happened. Exit 3, not 1: this is a solve/setup path, and a connector created
        # unbound here would reach CONNECTED and quietly scan nothing.
        self.assertEqual(self._exit(wz.cmd_connector_ensure,
                                    ["--account-id", "111111111111", "--session", "x",
                                     "--outpost-name", "lab-x", "--scanner-role-arn", "arn:s"],
                                    outposts=None), 3)

    def test_ensure_is_a_no_op_when_already_bound_to_that_outpost(self):
        with mock.patch.object(wz, "find_connector",
                               return_value=[self._node({"id": "o1", "name": "lab-x"})]), \
             mock.patch.object(wz, "api") as api, exits() as cm:
            wz.cmd_connector_ensure(["--account-id", "111111111111", "--outpost-id", "o1",
                                     "--scanner-role-arn", "arn:s", "--role-arn",
                                     "arn:aws:iam::111111111111:role/WizAccess-Role"])
        self.assertEqual(cm.code, 0)
        api.assert_not_called()

    def test_ensure_binds_an_existing_unbound_connector(self):
        calls = []
        self.assertEqual(self._exit(wz.cmd_connector_ensure,
                                    ["--account-id", "111111111111", "--outpost-id", "o1",
                                     "--scanner-role-arn", "arn:s", "--role-arn", "arn:r"],
                                    self._node(None),
                                    api=lambda q, v: (calls.append((q, v)), ({}, "tid"))[1]), 0)
        patch = calls[0][1]["input"]["patch"]["authParams"]
        self.assertEqual(patch["outpostId"], "o1")
        self.assertEqual(patch["diskAnalyzer"], {"scanner": {"roleARN": "arn:s"}})


class ServiceAccountGrading(unittest.TestCase):
    """The on-the-fly wizcli credential is a CLI DEPLOYMENT (createCliDeployment) — createServiceAccount
    (type:CLI) is rejected live. Lock the delete-then-mint convergence, the WIZ_CLIENT_ID/SECRET emit
    (clientId from the deployment's SA, secret from the payload), and the exit contract."""

    ENV: typing.ClassVar = {"INSTRUQT_SESSION_ID": "x"}

    def _wiz(self, existing=False, cid="cidX", sec="secX"):
        return FakeWiz(
            deployments={"nodes": [{"id": "dep1", "name": "lab-x-cli", "type": "WIZ_CLI"}] if existing else []},
            createCliDeployment={"clientSecret": sec, "deployment": {
                "id": "dep2", "name": "lab-x-cli", "type": "WIZ_CLI",
                "object": {"serviceAccount": {"name": "lab-x-cli-deployment-u", "clientId": cid}}}},
            deleteCliDeployment={"id": "dep1"})

    def _run(self, fn, argv, wiz):
        out = io.StringIO()
        return exit_code(fn, argv, wiz=wiz, env=self.ENV, out=out), out.getvalue()

    def test_ensure_creates_and_emits_client_creds(self):
        code, out = self._run(wz.cmd_serviceaccount_ensure, [], self._wiz(existing=False))
        self.assertEqual(code, 0)
        self.assertIn("WIZ_CLIENT_ID=cidX", out)
        self.assertIn("WIZ_CLIENT_SECRET=secX", out)

    def test_ensure_deletes_existing_before_minting(self):
        wiz = self._wiz(existing=True)
        code, _ = self._run(wz.cmd_serviceaccount_ensure, [], wiz)
        self.assertEqual(code, 0)
        mutations = [f for f, _ in wiz.calls if f.startswith(("delete", "create"))]
        self.assertEqual(mutations, ["deleteCliDeployment", "createCliDeployment"])

    def test_ensure_missing_creds_is_environment_3(self):
        code, _ = self._run(wz.cmd_serviceaccount_ensure, [], self._wiz(existing=False, cid=None))
        self.assertEqual(code, 3)

    def test_inspect_exists_absent_and_bad_require(self):
        self.assertEqual(self._run(wz.cmd_serviceaccount_inspect, [], self._wiz(existing=True))[0], 0)
        self.assertEqual(self._run(wz.cmd_serviceaccount_inspect, [], self._wiz(existing=False))[0], 1)
        self.assertEqual(self._run(wz.cmd_serviceaccount_inspect, ["--require", "bogus"], self._wiz(True))[0], 2)

    def test_delete_by_name_and_noop_when_absent(self):
        self.assertEqual(self._run(wz.cmd_serviceaccount_delete, [], self._wiz(existing=True))[0], 0)
        self.assertEqual(self._run(wz.cmd_serviceaccount_delete, [], self._wiz(existing=False))[0], 0)


    def test_delete_by_id_sends_the_id_as_a_variable(self):
        hostile = 'dep1" }) { id } } mutation { deleteTenant(input: { id: "t'
        wiz = self._wiz()
        code, _ = self._run(wz.cmd_serviceaccount_delete, ["--id", hostile], wiz)
        self.assertEqual(code, 0)
        self.assertEqual(wiz.sent("deleteCliDeployment"), [{"id": hostile}])
        self.assertNotIn(hostile, "".join(wiz.docs))


class KeycloakUser(unittest.TestCase):
    def test_ensure_refuses_to_join_a_group_when_the_created_user_is_not_found(self):
        # A None re-lookup after a 201 used to PUT to users/None/groups/<gid>.
        calls = []

        def kc_call(method, url, token, body=None):
            calls.append((method, url))
            return 201, b""

        with mock.patch.object(wz, "_kc_session", return_value=("https://kc", "wiz", "tok", "u@x", "U")), \
             mock.patch.object(wz, "_kc_user_id", return_value=None), \
             mock.patch.object(wz, "_kc_call", kc_call), \
             mock.patch.object(wz, "_kc_group_id", return_value="g1"), \
             exits() as cm:
            wz.cmd_user_ensure([])
        self.assertEqual(cm.code, 3)
        self.assertEqual([m for m, _ in calls], ["POST"])
        self.assertFalse([u for _, u in calls if "/users/None/" in u])


class CodeScanGrading(unittest.TestCase):
    """code-scan inspect grades the TENANT verdict (WARN_BY_POLICY exits 0 at the CLI, so the exit
    code can't tell a finding from a pass). Lock published/pass/fail + the bounded poll."""

    ENV: typing.ClassVar = {"INSTRUQT_SESSION_ID": "x"}

    def _cicd_api(self, seq):
        it = iter(seq)  # one node-or-None per successive cicdScans call

        def side(query, variables):
            if "cicdScans(" in query:
                node = next(it)
                return {"cicdScans": {"nodes": ([node] if node else []), "totalCount": (1 if node else 0)}}, "tid"
            return {}, "tid"
        return side

    def _node(self, state="DONE", verdict=None):
        return {"id": "c1", "status": {"state": state, "verdict": verdict}}

    def _exit(self, argv, side):
        with mock.patch.dict(wz.os.environ, self.ENV, clear=True), \
             mock.patch.object(wz, "api", side_effect=side), \
             mock.patch.object(wz.time, "sleep", lambda *_: None), \
             exits() as cm:
            wz.cmd_codescan_inspect(argv)
        return cm.code

    def test_published_any_scan_exit_0(self):
        side = self._cicd_api([self._node(verdict="FAILED_BY_POLICY")])
        self.assertEqual(self._exit(["--require", "published"], side), 0)

    def test_published_none_within_timeout_exit_1(self):
        self.assertEqual(self._exit(["--require", "published", "--timeout", "0"], self._cicd_api([None])), 1)

    def test_pass_passed_exit_0(self):
        self.assertEqual(self._exit(["--require", "pass"], self._cicd_api([self._node(verdict="PASSED_BY_POLICY")])), 0)

    def test_pass_failed_exits_1_without_waiting(self):
        self.assertEqual(self._exit(["--require", "pass"], self._cicd_api([self._node(verdict="FAILED_BY_POLICY")])), 1)

    def test_pass_polls_running_then_passed(self):
        seq = [self._node(state="IN_PROGRESS", verdict=None), self._node(verdict="PASSED_BY_POLICY")]
        self.assertEqual(self._exit(["--require", "pass", "--interval", "0"], self._cicd_api(seq)), 0)

    def test_bad_require_exit_2(self):
        self.assertEqual(self._exit(["--require", "bogus"], self._cicd_api([None])), 2)

    def test_unsafe_tag_value_exit_2(self):
        self.assertEqual(self._exit(["--tag-value", "bad value!"], self._cicd_api([None])), 2)


class PolicyGrading(unittest.TestCase):
    """policy ensure builds a BLOCK/CLI IaC policy scoped to the live-resolved Dockerfile control.
    Lock idempotency, the input shape (enforcement + single-rule scope), and the exit contract."""

    ENV: typing.ClassVar = {"INSTRUQT_SESSION_ID": "x"}
    CTL: typing.ClassVar = [{"id": "ctl-1", "name": "Last User Is 'root'", "severity": "HIGH"}]

    def _wiz(self, existing=False, control=None, created_id="pol-1"):
        control = self.CTL if control is None else control
        return FakeWiz(
            cicdScanPolicies={"nodes": [{"id": "pol-1", "name": "block-root"}] if existing else []},
            cloudConfigurationRules={"nodes": control},
            createCICDScanPolicy={"scanPolicy": {"id": created_id, "name": "block-root"} if created_id else {}},
            deleteCICDScanPolicy={"id": "pol-1"})

    def _exit(self, fn, argv, wiz):
        return exit_code(fn, argv, wiz=wiz, env=self.ENV)

    def test_ensure_idempotent_when_present(self):
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "block-root"], self._wiz(existing=True)), 0)

    def test_ensure_creates_scoped_block_cli_policy(self):
        wiz = self._wiz(existing=False)
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "block-root"], wiz), 0)
        inp = wiz.sent("createCICDScanPolicy")[0]["input"]
        self.assertEqual(inp["policyLifecycleEnforcements"],
                         [{"enforcementMethod": "BLOCK", "deploymentLifecycle": "CLI"}])
        self.assertEqual(inp["iacParams"]["cloudConfigurationRules"], ["ctl-1"])
        self.assertEqual(inp["iacParams"]["severityThreshold"], "HIGH")
        self.assertEqual(inp["iacParams"]["countThreshold"], 1)  # 0 is rejected live
        self.assertFalse(inp["default"])

    def test_ensure_control_absent_is_environment_3(self):
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "b"], self._wiz(existing=False, control=[])), 3)

    def test_ensure_refuses_a_control_that_is_not_the_documented_one(self):
        # `search` is a server-side contains. Scoping the policy to whatever it returned first built a
        # fixture that blocks on another condition while the lab still tells the learner to fix USER.
        other = [{"id": "ctl-9", "name": "Last User Is Not Declared", "severity": "HIGH"}]
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "b"], self._wiz(False, control=other)), 3)

    def test_ensure_refuses_two_controls_with_the_documented_name(self):
        dupes = [dict(self.CTL[0]), {"id": "ctl-2", "name": "Last User Is 'root'", "severity": "HIGH"}]
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "b"], self._wiz(False, control=dupes)), 3)

    def test_rule_id_override_scopes_without_a_lookup(self):
        wiz = self._wiz(existing=False, control=[])
        argv = ["--name", "block-root", "--rule-id", "ctl-chosen"]
        self.assertEqual(self._exit(wz.cmd_policy_ensure, argv, wiz), 0)
        created = wiz.sent("createCICDScanPolicy")[0]["input"]
        self.assertEqual(created["iacParams"]["cloudConfigurationRules"], ["ctl-chosen"])
        self.assertEqual(wiz.sent("cloudConfigurationRules"), [])

    def test_ensure_create_no_id_is_environment_3(self):
        wiz = self._wiz(existing=False, created_id=None)
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "b"], wiz), 3)

    def test_inspect_exists_absent_and_bad_require(self):
        self.assertEqual(self._exit(wz.cmd_policy_inspect, ["--name", "block-root"], self._wiz(existing=True)), 0)
        self.assertEqual(self._exit(wz.cmd_policy_inspect, ["--name", "block-root"], self._wiz(existing=False)), 1)
        self.assertEqual(self._exit(wz.cmd_policy_inspect, ["--name", "b", "--require", "x"], self._wiz(True)), 2)

    def test_delete_found_and_noop_when_absent(self):
        self.assertEqual(self._exit(wz.cmd_policy_delete, ["--name", "block-root"], self._wiz(existing=True)), 0)
        self.assertEqual(self._exit(wz.cmd_policy_delete, ["--name", "block-root"], self._wiz(existing=False)), 0)

    def test_missing_name_is_invocation_error_2(self):
        self.assertEqual(self._exit(wz.cmd_policy_inspect, [], self._wiz(existing=True)), 2)


class LeaseDevAccess(unittest.TestCase):
    """The dev path's contract: a transport/auth gap is 3 (INCONCLUSIVE), a not-yet-joined grader is
    1 (a wait), no key material is ever logged or published, and delete revokes before it drops the
    reference. Both halves move together — a tailnet key without a pubkey yields a node with no
    shell, and a pubkey without a key yields nothing at all."""

    def _exit(self, fn, args):
        return exit_code(fn, args)

    def test_secret_names_are_per_lab_and_drop_the_te_prefix(self):
        self.assertEqual(wz._secret_names(["--lab", "te-wiz-code-201"]),
                         ("TS_AUTHKEY_WIZ_CODE_201", "TE_DEV_SSH_PUBKEY_WIZ_CODE_201"))
        self.assertEqual(wz._secret_names(["--lab", "te-dev-aws"]),
                         ("TS_AUTHKEY_DEV_AWS", "TE_DEV_SSH_PUBKEY_DEV_AWS"))

    def test_missing_lab_is_invocation_error_2(self):
        self.assertEqual(self._exit(wz.cmd_lease_delete, []), 2)

    def test_missing_operator_token_is_environment_3(self):
        with mock.patch.dict(wz.os.environ, {"TAILSCALE_API_KEY": "", "INSTRUQT_API": ""}, clear=False):
            self.assertEqual(self._exit(wz.cmd_lease_verify, ["--no-self"]), 3)

    def test_inspect_not_yet_joined_is_1_not_3(self):
        with mock.patch.object(wz, "_fresh_nodes", return_value=[]):
            self.assertEqual(self._exit(wz.cmd_lease_inspect, ["--lab", "te-dev-aws", "--session", "s1"]), 1)

    def test_inspect_emits_grader_ip_and_the_key_that_opens_it(self):
        out = io.StringIO()
        with mock.patch.object(wz, "_fresh_nodes", return_value=[(5.0, "100.64.0.7", "grader-aws-s1")]), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
             exits() as cm:
            wz.cmd_lease_inspect(["--lab", "te-dev-aws", "--session", "s1"])
        self.assertEqual(cm.code, 0)
        self.assertIn("GRADER_IP=100.64.0.7", out.getvalue())
        self.assertIn("LEASE_SSH_KEY=", out.getvalue())  # an IP with no key is not access

    def test_inspect_refuses_an_ambiguous_match(self):
        # Two live graders on one substring: the freshest is another play's node as often as ours.
        two = [(5.0, "100.64.0.7", "awsconn101-aaa"), (9.0, "100.64.0.8", "awsconn101-bbb")]
        err = io.StringIO()
        with mock.patch.object(wz, "_fresh_nodes", return_value=two), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err), \
             exits() as cm:
            wz.cmd_lease_inspect(["--lab", "te-dev-aws", "--hostname", "awsconn101-"])
        self.assertEqual(cm.code, 3)
        self.assertIn("awsconn101-aaa", err.getvalue())
        self.assertIn("awsconn101-bbb", err.getvalue())

    def test_stale_node_is_not_reachable(self):
        # lastSeen freshness is the ONLY liveness signal: an ephemeral node lingers ~30 min after its
        # play, so an age-blind lookup hands the validator a dead grader.
        old = (wz.datetime.datetime.now(wz.datetime.UTC)
               - wz.datetime.timedelta(seconds=wz._NODE_FRESH_S + 60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        devices = {"devices": [{"hostname": "grader-aws-s1", "addresses": ["100.64.0.7"], "lastSeen": old}]}
        with mock.patch.object(wz, "_ts", return_value=devices):
            self.assertEqual(wz._fresh_nodes("s1"), [])

    @staticmethod
    def _ts_stub(keys, revoked, key="tskey-auth-SUPERSECRET"):
        def ts(method, path, body=None, **k):
            if method == "GET":
                return {"keys": keys}
            if method == "DELETE":
                revoked.append(path.rsplit("/", 1)[1])
                return {}
            return {"id": "kNEW", "key": key}
        return ts

    def _ensure(self, ts, iq, args, keypair=("/tmp/k/id_ed25519", "ssh-ed25519 AAAAPUB test"),
                joined="joined"):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(wz, "_ts", ts), mock.patch.object(wz, "_iq", iq), \
             mock.patch.object(wz, "_mint_keypair", return_value=(wz.pathlib.Path(keypair[0]), keypair[1])), \
             mock.patch.object(wz, "_self_join", return_value=joined), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
             exits() as cm:
            wz.cmd_lease_ensure(args)
        return cm.code, out.getvalue() + err.getvalue()

    def test_ensure_publishes_both_halves_and_logs_no_key_material(self):
        keys = [{"id": "kOLD", "description": "dev-te-dev-aws-aaaaaaaa"},
                {"id": "kOTHER", "description": "dev-te-wiz-code-201-bbbbbbbb"}]
        revoked, sent = [], []
        code, logged = self._ensure(self._ts_stub(keys, revoked), lambda q, v: sent.append(v) or {},
                                   ["--lab", "te-dev-aws", "--timelimit-seconds", "3600"])
        self.assertEqual(code, 0)
        self.assertEqual(revoked, ["kOLD"])  # this lab's prior key only — never another lab's
        pushed = {s["n"]: base64.b64decode(s["s"]).decode() for s in sent}
        self.assertEqual(pushed, {"TS_AUTHKEY_DEV_AWS": "tskey-auth-SUPERSECRET",
                                  "TE_DEV_SSH_PUBKEY_DEV_AWS": "ssh-ed25519 AAAAPUB test"})
        self.assertNotIn("SUPERSECRET", logged)

    def test_ensure_never_publishes_the_private_half(self):
        # The private key is the one thing that must stay on the operator box: in the team store it is
        # readable by anything that can render a secret into a sandbox. `_mint_keypair` is real here —
        # a stub cannot prove what the real one writes — but `_self_join` must stay patched: unpatched,
        # this test shells out to a real `tailscale up` and blocks on the control plane.
        sent = []
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(wz.os.environ, {"WIZLAB_LEASE_DIR": d}, clear=False), \
             mock.patch.object(wz, "_ts", self._ts_stub([], [])), \
             mock.patch.object(wz, "_self_join", return_value="joined"), \
             mock.patch.object(wz, "_iq", lambda q, v, **k: sent.append(v) or {}), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
             exits():
            wz.cmd_lease_ensure(["--lab", "te-dev-aws"])
        for s in sent:
            self.assertNotIn("PRIVATE KEY", base64.b64decode(s["s"]).decode())

    def test_ensure_rolls_back_the_whole_set_when_a_push_fails(self):
        # A live key nothing references is the worst outcome: the play that would have consumed it
        # does not exist, so it is a standing credential with no owner. A half-pushed pair burns a play.
        revoked, dropped = [], []

        def iq(q, v, **k):
            if "deleteTeamSecret" in q:
                dropped.append(v["n"])
                return {}
            wz.die(3, "instruqt: 502")

        self._ensure(self._ts_stub([], revoked, key="tskey-auth-X"), iq, ["--lab", "te-dev-aws"])
        self.assertEqual(revoked, ["kNEW"])
        self.assertEqual(sorted(dropped), ["TE_DEV_SSH_PUBKEY_DEV_AWS", "TS_AUTHKEY_DEV_AWS"])

    def test_delete_revokes_before_dropping_either_secret(self):
        order = []

        def ts(method, path, body=None, **k):
            if method == "DELETE":
                order.append("revoke")
            return {"keys": [{"id": "kNEW", "description": "dev-te-dev-aws-cccccccc"}]}

        with mock.patch.object(wz, "_ts", ts), \
             mock.patch.object(wz, "_iq", lambda q, v, **k: order.append(v["n"]) or {}):
            self.assertEqual(self._exit(wz.cmd_lease_delete, ["--lab", "te-dev-aws"]), 0)
        self.assertEqual(order, ["revoke", "TS_AUTHKEY_DEV_AWS", "TE_DEV_SSH_PUBKEY_DEV_AWS"])

    def test_ensure_leaves_a_similarly_prefixed_labs_key_alone(self):
        # `dev-te-dev-aws-` prefixes `dev-te-dev-aws-extra-<tag>`: a prefix test revoked the other lab's
        # key while its play was running.
        keys = [{"id": "kOWN", "description": "dev-te-dev-aws-aaaaaaaa"},
                {"id": "kEXTRA", "description": "dev-te-dev-aws-extra-bbbbbbbb"}]
        revoked = []
        code, _ = self._ensure(self._ts_stub(keys, revoked), lambda q, v: {}, ["--lab", "te-dev-aws"])
        self.assertEqual(code, 0)
        self.assertEqual(revoked, ["kOWN"])

    def test_delete_revokes_every_key_this_lab_owns_and_only_those(self):
        keys = [{"id": "kA", "description": "dev-te-dev-aws-aaaaaaaa"},
                {"id": "kB", "description": "dev-te-dev-aws-dddddddd"},
                {"id": "kEXTRA", "description": "dev-te-dev-aws-extra-bbbbbbbb"}]
        revoked = []
        with mock.patch.object(wz, "_ts", self._ts_stub(keys, revoked)), \
             mock.patch.object(wz, "_iq", lambda q, v, **k: {}):
            self.assertEqual(self._exit(wz.cmd_lease_delete, ["--lab", "te-dev-aws"]), 0)
        self.assertEqual(revoked, ["kA", "kB"])  # leaving one live leaves a way onto the tailnet

    def test_delete_removes_the_local_private_key(self):
        with tempfile.TemporaryDirectory() as d:
            priv = pathlib.Path(d) / "te-dev-aws" / "id_ed25519"
            priv.parent.mkdir(parents=True)
            priv.write_text("PRIVATE")
            priv.with_suffix(".pub").write_text("PUB")
            with mock.patch.dict(wz.os.environ, {"WIZLAB_LEASE_DIR": d}, clear=False), \
                 mock.patch.object(wz, "_ts", return_value={"keys": []}), \
                 mock.patch.object(wz, "_iq", lambda q, v, **k: {}):
                self.assertEqual(self._exit(wz.cmd_lease_delete, ["--lab", "te-dev-aws"]), 0)
            self.assertFalse(priv.exists())
            self.assertFalse(priv.with_suffix(".pub").exists())

    def test_delete_is_idempotent_when_both_sides_are_already_gone(self):
        # Absent is the tolerated answer (None from _iq, 404 from _ts), not a swallowed failure.
        out = io.StringIO()
        code = exit_code(wz.cmd_lease_delete, ["--lab", "te-dev-aws", "--key-id", "kOLD"], out=out,
                         _ts=lambda m, p, body=None, tolerate=None: None if m == "DELETE" else {"keys": []},
                         _iq=lambda q, v, **k: None)
        self.assertEqual(code, 0)
        self.assertIn("revoked kOLD; dropped (no secrets)", out.getvalue())

    def test_delete_reports_a_failed_revocation_and_drops_nothing(self):
        # The design review's F8 probe, inverted: a revoke the API refused is exit 3, the secrets and
        # the private key stay so a re-run can retry, and nothing prints "revoked".
        dropped = []

        def ts(method, path, body=None, **k):
            if method == "DELETE":
                wz.die(3, "tailscale HTTP 500: boom")
            return {"keys": [{"id": "kA", "description": "dev-te-dev-aws-aaaaaaaa"}]}
        priv = pathlib.Path(os.environ["WIZLAB_LEASE_DIR"]) / "te-dev-aws" / "id_ed25519"
        priv.parent.mkdir(parents=True, exist_ok=True)
        priv.write_text("PRIVATE")
        out, err = io.StringIO(), io.StringIO()
        code = exit_code(wz.cmd_lease_delete, ["--lab", "te-dev-aws"], out=out, err=err,
                         _ts=ts, _iq=lambda q, v, **k: dropped.append(v["n"]) or {})
        self.assertEqual(code, 3)
        self.assertEqual(dropped, [])
        self.assertNotIn("revoked", out.getvalue())
        self.assertIn("kA not revoked", err.getvalue())
        self.assertTrue(priv.exists())
        priv.unlink()

    def test_delete_reports_a_secret_that_would_not_drop(self):
        def iq(q, v, **k):
            wz.die(3, "instruqt: 502")
        err = io.StringIO()
        code = exit_code(wz.cmd_lease_delete, ["--lab", "te-dev-aws"], err=err, _ts={"keys": []}, _iq=iq)
        self.assertEqual(code, 3)
        self.assertIn("TS_AUTHKEY_DEV_AWS not dropped", err.getvalue())

    def _join(self, state, proc, key="tskey-auth-SUPERSECRET"):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(wz.os.environ, {"WIZLAB_LEASE_DIR": d}, clear=False), \
             mock.patch.object(wz, "_backend_state", return_value=state), \
             mock.patch.object(wz.subprocess, "run", return_value=proc) as run:
            msg = wz._self_join(["--lab", "te-dev-aws"], key)
            argv = run.call_args[0][0] if run.call_args else []
            leftover = sorted(p.name for p in (pathlib.Path(d) / "te-dev-aws").glob("*"))
        return msg, argv, leftover

    def test_self_join_passes_the_key_by_path_never_in_argv(self):
        # /proc/<pid>/cmdline is world-readable, so a key in argv is readable by any local user for
        # as long as the process lives.
        msg, argv, leftover = self._join("needslogin", _proc(0))
        self.assertEqual(msg, "joined this host to the tailnet")
        self.assertIn("--auth-key=file:", " ".join(argv))
        self.assertNotIn("SUPERSECRET", " ".join(argv))
        self.assertEqual(leftover, [])  # consumed key file is removed on success

    def test_self_join_leaves_a_running_host_alone(self):
        # Re-upping with a per-play ephemeral key would churn a durable node identity for nothing.
        msg, argv, _ = self._join("running", _proc(0))
        self.assertEqual(msg, "already on the tailnet")
        self.assertEqual(argv, [])

    def test_self_join_failure_is_a_warning_naming_the_command(self):
        # The lease is already real by this point; only local membership is missing, and `verify` is
        # what refuses to grade over a tunnel that is not there.
        msg, _, leftover = self._join("needslogin", _proc(1, stderr="sudo: a password is required"))
        self.assertIn("NOT joined", msg)
        self.assertIn("sudo tailscale up --auth-key=file:", msg)
        self.assertNotIn("SUPERSECRET", msg)
        self.assertEqual(leftover, ["authkey"])  # left for the operator to run the command with

    def test_ensure_exits_0_even_when_the_local_join_fails(self):
        sent = []
        code, logged = self._ensure(self._ts_stub([], []), lambda q, v, **k: sent.append(v) or {},
                                   ["--lab", "te-dev-aws"], joined="NOT joined (sudo)")
        self.assertEqual(code, 0)
        self.assertIn("NOT joined", logged)
        self.assertEqual(len(sent), 2)  # both secrets still pushed

    @unittest.skipUnless(shutil.which("ssh-keygen"), "openssh-client absent")
    def test_minted_keypair_is_a_real_ed25519_pair_the_private_half_locked_down(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(wz.os.environ, {"WIZLAB_LEASE_DIR": d}, clear=False):
            priv, pub = wz._mint_keypair(["--lab", "te-dev-aws"])
            self.assertTrue(pub.startswith("ssh-ed25519 "))
            self.assertEqual(priv.stat().st_mode & 0o777, 0o600)
            first = pub
            # Fresh per play: a second ensure must not reuse the key the last play's grader trusted.
            self.assertNotEqual(wz._mint_keypair(["--lab", "te-dev-aws"])[1], first)

    def test_verify_spends_the_tailscale_token_not_just_reads_the_env(self):
        # A revoked-but-present token passes every local check and then fails at mint, burning a play.
        calls = []
        with mock.patch.dict(wz.os.environ, {"TAILSCALE_API_KEY": "x", "INSTRUQT_API": "y"}), \
             mock.patch.object(wz, "_ts", lambda m, p, b=None: calls.append(("ts", p)) or {"keys": []}), \
             mock.patch.object(wz, "_iq", lambda q, v, **k: calls.append(("iq", None)) or {}), \
             mock.patch.object(wz, "_self_on_tailnet", lambda: None), \
             contextlib.redirect_stdout(io.StringIO()), exits() as cm:
            wz.cmd_lease_verify([])
        self.assertEqual(cm.code, 0)
        self.assertIn("ts", [c[0] for c in calls])   # the Tailscale API was actually reached
        self.assertIn("iq", [c[0] for c in calls])

    def test_verify_is_3_when_the_tailscale_token_is_revoked(self):
        def dead_ts(m, p, b=None):
            wz.die(3, "tailscale: 401")
        with mock.patch.dict(wz.os.environ, {"TAILSCALE_API_KEY": "revoked", "INSTRUQT_API": "y"}), \
             mock.patch.object(wz, "_ts", dead_ts), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
             exits() as cm:
            wz.cmd_lease_verify([])
        self.assertEqual(cm.code, 3)

    def test_an_api_access_token_is_never_a_sweepable_lease_key(self):
        # `/keys` returns API access tokens next to device auth keys; only `capabilities.devices.create`
        # separates them. Revoking the one TAILSCALE_API_KEY holds locks every lease verb out of the API
        # and cannot be undone from the CLI, so the sweep must not be able to select one.
        token = {"id": "kTOKEN", "description": "dev-te-dev-aws-tok", "capabilities": {}}
        authkey = {"id": "kAUTH", "description": "dev-te-dev-aws-aaaa",
                   "capabilities": {"devices": {"create": {"reusable": True}}}}
        with mock.patch.object(wz, "_ts", lambda m, p, b=None: {"keys": [token, authkey]}):
            self.assertEqual([k["id"] for k in wz._lease_keys()], ["kAUTH"])

    def test_a_list_payload_without_capabilities_still_sweeps(self):
        # Capabilities are not always summarized in the list response; dropping such keys would silently
        # strand every prior lease key as an unrevokable orphan.
        with mock.patch.object(wz, "_ts",
                               lambda m, p, b=None: {"keys": [{"id": "kA", "description": "dev-te-dev-aws-a"}]}):
            self.assertEqual([k["id"] for k in wz._lease_keys()], ["kA"])

    def test_scrub_masks_any_key_shaped_string(self):
        self.assertNotIn("abc123", wz._scrub("up --authkey=tskey-auth-abc123 failed"))


class RunnerFloor(unittest.TestCase):
    """`session verify --min-runner` turns a lab's floor comment into something that fails."""

    def _verify(self, args, env):
        with mock.patch.dict(wz.os.environ, env, clear=False), \
             mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid")), \
             mock.patch.object(wz, "api", return_value=({"connectors": {"totalCount": 0}}, "tid")), \
             contextlib.redirect_stdout(io.StringIO()) as out, \
             contextlib.redirect_stderr(io.StringIO()) as err, \
             exits() as cm:
            wz.cmd_session_verify(args)
        return cm.code, out.getvalue(), err.getvalue()

    def test_version_compares_as_ints_not_lexicographically(self):
        # The whole point: "v0.1.9" > "v0.1.36" as strings, so a floor of v0.1.29 would pass on v0.1.9.
        self.assertLess(wz._version("v0.1.9"), wz._version("v0.1.36"))
        self.assertEqual(wz._version("v0.1.36"), (0, 1, 36))
        self.assertIsNone(wz._version("latest"))

    def test_a_pin_at_or_above_the_floor_passes(self):
        for tag in ("v0.1.29", "v0.1.37"):
            code, _out, _err = self._verify(["--min-runner", "v0.1.29"], {"TE_RUNNER_TAG": tag})
            self.assertEqual(code, 0, tag)

    def test_a_pin_below_the_floor_is_an_invocation_error_not_a_learner_failure(self):
        # 2, so a validator reads FAIL (the lab's own pin is wrong) rather than INCONCLUSIVE.
        code, _out, err = self._verify(["--min-runner", "v0.1.33"], {"TE_RUNNER_TAG": "v0.1.29"})
        self.assertEqual(code, 2)
        self.assertIn("below this lab's floor", err)

    def test_the_floor_is_checked_before_any_credential_is_spent(self):
        with mock.patch.dict(wz.os.environ, {"TE_RUNNER_TAG": "v0.1.29"}, clear=False), \
             mock.patch.object(wz, "token_and_dc") as tok, \
             contextlib.redirect_stderr(io.StringIO()), exits() as cm:
            wz.cmd_session_verify(["--min-runner", "v0.1.33"])
        self.assertEqual(cm.code, 2)
        tok.assert_not_called()

    def test_a_runner_that_cannot_name_itself_is_environment_never_a_pass(self):
        code, _out, err = self._verify(["--min-runner", "v0.1.29"], {"TE_RUNNER_TAG": ""})
        self.assertEqual(code, 3)
        self.assertIn("unknowable", err)

    def test_a_floor_that_is_not_a_version_is_an_invocation_error(self):
        code, _out, _err = self._verify(["--min-runner", "latest"], {"TE_RUNNER_TAG": "v0.1.37"})
        self.assertEqual(code, 2)

    def test_no_floor_flag_leaves_verify_unchanged(self):
        code, out, _err = self._verify([], {"TE_RUNNER_TAG": "v0.1.37", "TE_RUNNER_REV": "deadbeefcafe"})
        self.assertEqual(code, 0)
        # Check 1's line is the only record of what a play actually ran.
        self.assertIn("runner=v0.1.37@deadbee", out)

    def test_identity_falls_back_to_pid_1_when_the_shell_env_was_scrubbed(self):
        # sshd's sessions carry none of the image's ENV, so a validator over the tailnet would fail
        # every floor as exit 3 without this.
        environ = b"PATH=/usr/bin\x00TE_RUNNER_TAG=v0.1.38\x00TE_RUNNER_REV=abc1234\x00"
        with mock.patch.dict(wz.os.environ, {"TE_RUNNER_TAG": "", "TE_RUNNER_REV": ""}, clear=False), \
             mock.patch.object(wz.pathlib.Path, "read_bytes", lambda self: environ):
            self.assertEqual(wz._runner_id(), ("v0.1.38", "abc1234"))

    def test_the_shell_env_wins_over_pid_1(self):
        with mock.patch.dict(wz.os.environ, {"TE_RUNNER_TAG": "v0.1.40", "TE_RUNNER_REV": "dd"}), \
             mock.patch.object(wz.pathlib.Path, "read_bytes",
                               lambda self: b"TE_RUNNER_TAG=v0.1.1\x00"):
            self.assertEqual(wz._runner_id(), ("v0.1.40", "dd"))

    def test_no_pid_1_to_read_is_an_absent_identity_not_a_crash(self):
        with mock.patch.dict(wz.os.environ, {"TE_RUNNER_TAG": "", "TE_RUNNER_REV": ""}, clear=False), \
             mock.patch.object(wz.pathlib.Path, "read_bytes",
                               lambda self: (_ for _ in ()).throw(OSError("no /proc"))):
            self.assertEqual(wz._runner_id(), ("", ""))

    def test_an_unidentified_runner_still_verifies_without_the_flag(self):
        code, out, _err = self._verify([], {"TE_RUNNER_TAG": "", "TE_RUNNER_REV": ""})
        self.assertEqual(code, 0)
        self.assertIn("runner=unknown", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
