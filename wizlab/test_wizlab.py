#!/usr/bin/env python3
# Stdlib-only harness (no external deps, matching wizlab). Locks the load-bearing invariants so
# refactors are safe without re-playing a lab: the 0/1/2/3 exit-code contract, IAM-trust parsing
# breadth, flag edges, and the main() dispatch guard. Run: python wizlab/test_wizlab.py
import contextlib
import io
import json
import pathlib
import types
import typing
import unittest
import urllib.error
from importlib.machinery import SourceFileLoader
from unittest import mock

wz = SourceFileLoader("wizlab_cli", str(pathlib.Path(__file__).resolve().parent / "wizlab")).load_module()


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
        with self.assertRaises(SystemExit) as cm:
            wz._flag(["role", "inspect", "--role-name"], "--role-name")
        self.assertEqual(cm.exception.code, 2)


class CliHelper(unittest.TestCase):
    def test_missing_binary_is_environment_3(self):
        # FileNotFoundError must map to exit 3, not bubble as an uncaught exception (which would be 2).
        with mock.patch.object(wz.subprocess, "run", side_effect=FileNotFoundError), \
             self.assertRaises(SystemExit) as cm:
            wz._cli("no-such-binary", "version")
        self.assertEqual(cm.exception.code, 3)

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
             self.assertRaises(SystemExit) as cm:
            wz._post("https://x/", "d", {}, attempts=3)
        self.assertEqual(cm.exception.code, 3)
        self.assertEqual(op.call_count, 3)  # retried, not one-shot

    def test_post_4xx_fails_fast(self):
        err = urllib.error.HTTPError("u", 400, "bad", None, io.BytesIO(b"nope"))
        op = mock.MagicMock(side_effect=err)
        with mock.patch.object(wz.urllib.request, "urlopen", op), mock.patch.object(wz.time, "sleep"), \
             self.assertRaises(SystemExit) as cm:
            wz._post("https://x/", "d", {}, attempts=3)
        self.assertEqual(cm.exception.code, 3)
        self.assertEqual(op.call_count, 1)  # 4xx is not transient — no retry

    def test_main_bad_verb_is_invocation_error(self):
        with mock.patch.object(wz.sys, "argv", ["wizlab", "bogus", "verb"]), self.assertRaises(SystemExit) as cm:
            wz.main()
        self.assertEqual(cm.exception.code, 2)

    def test_main_guards_uncaught_exception_as_2(self):
        boom = mock.MagicMock(side_effect=RuntimeError("kaboom"))
        with mock.patch.dict(wz.VERBS, {("session", "verify"): boom}), \
             mock.patch.object(wz.sys, "argv", ["wizlab", "session", "verify"]), \
             self.assertRaises(SystemExit) as cm:
            wz.main()
        self.assertEqual(cm.exception.code, 2)  # bug, not a raw traceback exiting 1

    def test_user_inspect_group_transport_failure_is_environment_3(self):
        session = wz._KcSession("https://kc", "realm", "tok", "lab-s1@example.com", "lab-s1")
        with mock.patch.object(wz, "_kc_session", return_value=session), \
             mock.patch.object(wz, "_kc_user_id", return_value="u1"), \
             mock.patch.object(wz, "_kc_call", return_value=(503, b"unavailable")), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_user_inspect(["--session", "s1"])
        self.assertEqual(cm.exception.code, 3)


class RoleInspectGrading(unittest.TestCase):
    DELEGATOR = "arn:aws:iam::851725410668:role/prod-us100-AssumeRoleDelegator"
    TID = "6ca852a0-af83-4f2d-9da9-f2f3bd1d23a3"

    def _run(self, aws_proc, delegator=DELEGATOR, tid=TID):
        with mock.patch.object(wz, "_aws", return_value=aws_proc), \
             mock.patch.object(wz, "_wiz_delegator", return_value=(delegator, tid)), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_role_inspect([])
        return cm.exception.code

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


class Naming(unittest.TestCase):
    def test_stem_is_session_scoped(self):
        self.assertEqual(wz._lab_stem("abc123"), "lab-abc123")

    def test_session_id_from_flag_then_env(self):
        self.assertEqual(wz._session_id(["--session", "flagid"]), "flagid")
        with mock.patch.dict(wz.os.environ, {"INSTRUQT_SESSION_ID": "envid"}, clear=False):
            self.assertEqual(wz._session_id([]), "envid")

    def test_session_id_missing_is_invocation_error(self):
        with mock.patch.dict(wz.os.environ, {}, clear=True), self.assertRaises(SystemExit) as cm:
            wz._session_id([])
        self.assertEqual(cm.exception.code, 2)

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

    def test_reap_one_refuses_ambiguous_match(self):
        # Shared-tenant safety: >1 name match must skip+alert, never delete — even with --commit.
        with mock.patch.object(wz, "_reap_handler", return_value={}), \
             mock.patch.object(wz, "_reap_find", return_value=(None, 2, None)):
            did, alert, blocked = wz._reap_one("tok", "dc", "CreateServiceAccount", "lab-s1-sa", True)
        self.assertFalse(did)
        self.assertIn("matched 2", alert)
        self.assertTrue(blocked)  # the resource is still there

    def test_reap_one_treats_an_already_gone_resource_as_a_no_op(self):
        # The reap window overlaps by design, so a second pass over a reaped session finds the audit
        # Create with no resource behind it. That must not alert, and must not block the user delete.
        with mock.patch.object(wz, "_reap_handler", return_value={}), \
             mock.patch.object(wz, "_reap_find", return_value=(None, 0, None)):
            did, alert, blocked = wz._reap_one("tok", "dc", "CreateReport", "lab-s1-report", True)
        self.assertEqual((did, alert, blocked), (False, None, False))

    def test_reap_one_does_not_block_on_an_unhandled_type(self):
        # No handler for the type: unactionable, so alert a human but never fail the run — the generic
        # plural+search handler misses most create types and this would otherwise fire every reap.
        with mock.patch.object(wz, "_reap_handler", return_value={}), \
             mock.patch.object(wz, "_reap_find", return_value=(None, None, "no such field")):
            did, alert, blocked = wz._reap_one("tok", "dc", "CreateWidget", "lab-s1-w", True)
        self.assertFalse(did)
        self.assertIn("no handler", alert)
        self.assertFalse(blocked)

    def test_reap_enumeration_surfaces_graphql_errors(self):
        with mock.patch.object(wz, "_gql", return_value=({}, [{"message": "denied"}])):
            actions, alert = wz._reap_enumerate("tok", "dc", "lab-s1@example.com", 60)
        self.assertEqual(actions, [])
        self.assertIn("denied", alert)

    def test_committed_reap_exits_3_when_enumeration_is_incomplete(self):
        with mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid")), \
             mock.patch.object(wz, "_reap_enumerate", return_value=([], "denied")), \
             mock.patch.object(wz, "_reap_sweep_type", return_value=(0, 0, 0)), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_reap(["--session", "s1", "--commit"])
        self.assertEqual(cm.exception.code, 3)

    def test_committed_reap_exits_3_when_a_sweep_lookup_fails(self):
        with mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid")), \
             mock.patch.object(wz, "_reap_enumerate", return_value=([], None)), \
             mock.patch.object(wz, "_reap_sweep_type", return_value=(0, 1, 1)), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_reap(["--session", "s1", "--commit"])
        self.assertEqual(cm.exception.code, 3)

    def test_committed_reap_exits_0_when_alerts_are_unactionable(self):
        # An alert a human should read is not the same as cleanup that did not happen: exiting 3 here
        # would make the reaper retain every lab-<sid>@ user it was built to delete.
        with mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid")), \
             mock.patch.object(wz, "_reap_enumerate", return_value=([("CreateWidget", "lab-s1-w")], None)), \
             mock.patch.object(wz, "_reap_one", return_value=(False, "ALERT no handler", False)), \
             mock.patch.object(wz, "_reap_sweep_type", return_value=(0, 0, 0)), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_reap(["--session", "s1", "--commit"])
        self.assertEqual(cm.exception.code, 0)

    def test_reap_one_alerts_when_delete_does_not_remove_resource(self):
        found = [("id1", 1, None), ("id1", 1, None)]
        with mock.patch.object(wz, "_reap_handler", return_value={"delete": "deleteReport", "soft": False}), \
             mock.patch.object(wz, "_reap_find", side_effect=found), \
             mock.patch.object(wz, "_gql", return_value=({}, [{"message": "denied"}])):
            did, alert, blocked = wz._reap_one("tok", "dc", "CreateReport", "lab-s1-report", True)
        self.assertFalse(did)
        self.assertIn("deletion did not remove", alert)
        self.assertTrue(blocked)

    def test_kc_user_id_refuses_multiple_exact(self):
        dup = json.dumps([{"id": "1", "username": "lab-s1@titra-labs.ai"},
                          {"id": "2", "email": "lab-s1@titra-labs.ai"}])
        with mock.patch.object(wz, "_kc_call", return_value=(200, dup)), self.assertRaises(SystemExit) as cm:
            wz._kc_user_id("http://kc", "realm", "tok", "lab-s1@titra-labs.ai")
        self.assertEqual(cm.exception.code, 3)

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
        with self.assertRaises(SystemExit) as cm:
            wz.cmd_wiz_type(["--name", "Type; DROP"])
        self.assertEqual(cm.exception.code, 2)


class CloudSelection(unittest.TestCase):
    """The AWS-blindness this fixes failed in the worst direction: a live CONNECTED GCP connector
    graded as "no connector targets", telling a learner they hadn't done what they had just done."""
    GCP_NODE: typing.ClassVar = {"id": "g", "name": "lab-s1-connector", "enabled": True,
                                 "status": "CONNECTED", "type": {"id": "gcp"},
                                 "config": {"projectId": "wiz-lab-42"}}

    def test_default_is_aws_and_bad_value_is_invocation_error(self):
        self.assertEqual(wz._cloud([]), "aws")
        self.assertEqual(wz._cloud(["--cloud", "gcp"]), "gcp")
        with self.assertRaises(SystemExit) as cm:
            wz._cloud(["--cloud", "oracle"])
        self.assertEqual(cm.exception.code, 2)

    def test_gcp_connector_found_only_when_cloud_is_gcp(self):
        with mock.patch.object(wz, "api", return_value=({"connectors": {"nodes": [self.GCP_NODE]}}, "tid")):
            self.assertEqual([n["id"] for n in wz.find_connector("wiz-lab-42", "gcp")], ["g"])
            self.assertEqual(wz.find_connector("wiz-lab-42", "aws"), [])  # the old bug, locked down

    def test_gcp_inspect_healthy_exit_0(self):
        with mock.patch.object(wz, "find_connector", return_value=[self.GCP_NODE]), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_connector_inspect(["--cloud", "gcp", "--account-id", "wiz-lab-42", "--require", "healthy"])
        self.assertEqual(cm.exception.code, 0)

    def test_gcp_ensure_is_create_if_absent_never_patch(self):
        # No customerRoleARN equivalent to drift, so an existing connector is a no-op, not an update.
        with mock.patch.object(wz, "find_connector", return_value=[self.GCP_NODE]), \
             mock.patch.object(wz, "api") as api, self.assertRaises(SystemExit) as cm:
            wz.cmd_connector_ensure(["--cloud", "gcp", "--account-id", "wiz-lab-42"])
        self.assertEqual(cm.exception.code, 0)
        api.assert_not_called()

    def test_gcp_create_payload_is_managed_identity_with_empty_scopes(self):
        created = {"createConnector": {"connector": {"id": "n", "name": "lab-s1-connector", "status": "INITIAL"}}}
        with mock.patch.object(wz, "find_connector", return_value=[]), \
             mock.patch.object(wz, "api", return_value=(created, "tid")) as api, \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_connector_ensure(["--cloud", "gcp", "--account-id", "wiz-lab-42", "--session", "s1"])
        self.assertEqual(cm.exception.code, 0)
        payload = api.call_args[0][1]["input"]
        self.assertEqual(payload["type"], "gcp")
        self.assertEqual(payload["authParams"], {"isManagedIdentity": True, "project_id": "wiz-lab-42"})
        self.assertTrue(all(v == [] for v in payload["extraConfig"].values()))
        self.assertNotIn("customerRoleARN", json.dumps(payload))

    def test_unsupported_paths_refuse_rather_than_guess(self):
        with self.assertRaises(SystemExit) as cm:
            wz.cmd_connector_ensure(["--cloud", "azure", "--account-id", "sub-1"])
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit) as cm:  # provisioning belongs to terraform, not wizlab
            wz.cmd_role_ensure(["--cloud", "gcp"])
        self.assertEqual(cm.exception.code, 2)


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
             self.assertRaises(SystemExit) as cm:
            wz.api("mutation M { createConnector { id } }", {})
        self.assertEqual(cm.exception.code, 3)
        self.assertEqual(post.call_count, 1)

    def test_a_real_error_is_not_retried(self):
        bad = {"errors": [{"message": "Resource not found"}], "data": None}
        post = self._post_returning(bad, bad, bad)
        with mock.patch.object(wz, "token_and_dc", return_value=("t", "dc", "tid")), \
             mock.patch.object(wz, "_post", post), self.assertRaises(SystemExit) as cm:
            wz.api("query Q { x }", {})
        self.assertEqual(cm.exception.code, 3)
        self.assertEqual(post.call_count, 1)


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
             self.assertRaises(SystemExit) as cm:
            wz.find_connector("proj-1", "gcp", None)
        self.assertEqual(cm.exception.code, 3)

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
        with mock.patch.dict(wz.os.environ, {}, clear=True), self.assertRaises(SystemExit) as cm:
            wz.cmd_connector_ensure(["--cloud", "azure", "--account-id", self.SUB])
        self.assertEqual(cm.exception.code, 2)

    def test_ensure_payload_is_managed_identity_with_subscription_and_tenant(self):
        created = {"createConnector": {"connector": {"id": "n", "name": "lab-s1-connector", "status": "INITIAL"}}}
        with mock.patch.object(wz, "find_connector", return_value=[]), \
             mock.patch.object(wz, "api", return_value=(created, "tid")) as api, \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_connector_ensure(["--cloud", "azure", "--account-id", self.SUB,
                                     "--tenant-id", "dir-1", "--session", "s1"])
        self.assertEqual(cm.exception.code, 0)
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
             self.assertRaises(SystemExit) as cm:
            wz.cmd_role_inspect(argv if argv is not None else self.DEFAULT_ARGV)
        return cm.exception.code, az

    def test_both_roles_assigned_exit_0(self):
        code, az = self._run(_proc(0, json.dumps(["Reader", "WizCustomRole"])))
        self.assertEqual(code, 0)
        # --fill-principal-name false is load-bearing: the default resolves names via Graph, which
        # Entra denies on this lease, so the call would fail for a non-learner reason.
        self.assertIn("--fill-principal-name", az.call_args[0])
        self.assertIn("false", az.call_args[0])

    def test_missing_role_name_flag_is_invocation_error(self):
        with mock.patch.dict(wz.os.environ, {"WIZ_TBCMP_AZURE_APP_OBJECT_ID": self.OID}, clear=True), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_role_inspect(["--cloud", "azure", "--account-id", self.SUB])
        self.assertEqual(cm.exception.code, 2)

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
             self.assertRaises(SystemExit) as cm:
            wz.cmd_wiz_tenant([])
        return cm.exception.code, out.getvalue()

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
             self.assertRaises(SystemExit) as cm:
            wz.cmd_session_verify([])
        self.assertEqual(cm.exception.code, 0)
        csp.assert_not_called()

    def test_unknown_cloud_is_invocation_error(self):
        with self._mock_wiz(), self._mock_api(), self.assertRaises(SystemExit) as cm:
            wz.cmd_session_verify(["--cloud", "oracle"])
        self.assertEqual(cm.exception.code, 2)

    def test_missing_csp_vars_exit_3(self):
        with self._mock_wiz(), self._mock_api(), \
             mock.patch.dict(wz.os.environ, {}, clear=True), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_session_verify(["--cloud", "aws"])
        self.assertEqual(cm.exception.code, 3)

    def test_csp_probe_failure_exit_3(self):
        env = {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y"}
        with self._mock_wiz(), self._mock_api(), \
             mock.patch.dict(wz.os.environ, env, clear=True), \
             mock.patch.object(wz, "_aws", return_value=_proc(1, "", "ExpiredToken")), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_session_verify(["--cloud", "aws"])
        self.assertEqual(cm.exception.code, 3)

    def test_csp_probe_success_exit_0(self):
        env = {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y"}
        with self._mock_wiz(), self._mock_api(), \
             mock.patch.dict(wz.os.environ, env, clear=True), \
             mock.patch.object(wz, "_aws", return_value=_proc(0, '{"Account": "123456789012"}')), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_session_verify(["--cloud", "aws"])
        self.assertEqual(cm.exception.code, 0)


class GcpRoleInspect(unittest.TestCase):
    SA = "wizdeadbeef@prod-us100.iam.gserviceaccount.com"

    def _policy(self, roles, member=None):
        member = member or f"serviceAccount:{self.SA}"
        return json.dumps({"bindings": [{"role": r, "members": [member]} for r in roles]})

    def _run(self, proc, sa=SA):
        with mock.patch.object(wz, "_gcp", return_value=proc), \
             mock.patch.object(wz, "_wiz_gcp_sa", return_value=sa), \
             self.assertRaises(SystemExit) as cm:
            wz.cmd_role_inspect(["--cloud", "gcp", "--account-id", "wiz-lab-42"])
        return cm.exception.code

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
        with mock.patch.object(wz, "api", side_effect=side), self.assertRaises(SystemExit) as cm:
            fn(argv)
        return cm.exception.code

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
        # A fake clock, not just a no-op sleep: the uninstall wait is bounded by time.time(), so a
        # patched-out sleep alone would spin on the real clock for the whole --timeout.
        clock = {"t": 1000.0}
        with mock.patch.object(wz, "api", side_effect=side), \
                mock.patch.object(wz.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s)), \
                mock.patch.object(wz.time, "time", lambda: clock["t"]), \
                self.assertRaises(SystemExit) as cm:
            fn(argv)
        return cm.exception.code

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
        with mock.patch.object(wz, "find_connector", return_value=[node] if node else []), \
             mock.patch.object(wz, "_resolve_outpost", return_value=outposts), \
             mock.patch.object(wz, "api", side_effect=api or (lambda q, v: ({}, "tid"))), \
             self.assertRaises(SystemExit) as cm:
            fn(argv)
        return cm.exception.code

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
             mock.patch.object(wz, "api") as api, self.assertRaises(SystemExit) as cm:
            wz.cmd_connector_ensure(["--account-id", "111111111111", "--outpost-id", "o1",
                                     "--scanner-role-arn", "arn:s", "--role-arn",
                                     "arn:aws:iam::111111111111:role/WizAccess-Role"])
        self.assertEqual(cm.exception.code, 0)
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
    """The on-the-fly Wiz CLI SA (type:CLI) shares the createServiceAccount path with the sensor;
    lock the idempotency, the WIZ_CLIENT_ID/SECRET emit, and the exit contract."""

    ENV: typing.ClassVar = {"INSTRUQT_SESSION_ID": "x"}

    def _sa_api(self, existing=False, created=("cid", "sec")):
        def side(query, variables):
            if "serviceAccounts(" in query:
                nodes = [{"id": "sa1", "name": "lab-x-cli"}] if existing else []
                return {"serviceAccounts": {"nodes": nodes}}, "tid"
            if "createServiceAccount" in query:
                cid, sec = created
                return {"createServiceAccount": {"serviceAccount": {
                    "id": "sa1", "name": "lab-x-cli", "clientId": cid, "clientSecret": sec}}}, "tid"
            if "deleteServiceAccount" in query:
                return {"deleteServiceAccount": {"_stub": True}}, "tid"
            return {}, "tid"
        return side

    def _run(self, fn, argv, side):
        out = io.StringIO()
        with mock.patch.dict(wz.os.environ, self.ENV, clear=True), \
             mock.patch.object(wz, "api", side_effect=side), \
             contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            fn(argv)
        return cm.exception.code, out.getvalue()

    def test_ensure_creates_and_emits_client_creds(self):
        code, out = self._run(wz.cmd_serviceaccount_ensure, [], self._sa_api(existing=False))
        self.assertEqual(code, 0)
        self.assertIn("WIZ_CLIENT_ID=cid", out)
        self.assertIn("WIZ_CLIENT_SECRET=sec", out)

    def test_ensure_idempotent_no_secret_reissued(self):
        code, out = self._run(wz.cmd_serviceaccount_ensure, [], self._sa_api(existing=True))
        self.assertEqual(code, 0)
        self.assertNotIn("WIZ_CLIENT_ID", out)

    def test_ensure_missing_creds_is_environment_3(self):
        code, _ = self._run(wz.cmd_serviceaccount_ensure, [], self._sa_api(existing=False, created=(None, None)))
        self.assertEqual(code, 3)

    def test_inspect_exists_absent_and_bad_require(self):
        self.assertEqual(self._run(wz.cmd_serviceaccount_inspect, [], self._sa_api(existing=True))[0], 0)
        self.assertEqual(self._run(wz.cmd_serviceaccount_inspect, [], self._sa_api(existing=False))[0], 1)
        self.assertEqual(self._run(wz.cmd_serviceaccount_inspect, ["--require", "bogus"], self._sa_api(True))[0], 2)

    def test_delete_by_name_and_noop_when_absent(self):
        self.assertEqual(self._run(wz.cmd_serviceaccount_delete, [], self._sa_api(existing=True))[0], 0)
        self.assertEqual(self._run(wz.cmd_serviceaccount_delete, [], self._sa_api(existing=False))[0], 0)


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
             self.assertRaises(SystemExit) as cm:
            wz.cmd_codescan_inspect(argv)
        return cm.exception.code

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

    def _api(self, existing=False, control=None, created_id="pol-1"):
        control = self.CTL if control is None else control
        self.created = {}

        def side(query, variables):
            if "cicdScanPolicies(" in query:
                nodes = [{"id": "pol-1", "name": "block-root"}] if existing else []
                return {"cicdScanPolicies": {"nodes": nodes}}, "tid"
            if "cloudConfigurationRules(" in query:
                return {"cloudConfigurationRules": {"nodes": control}}, "tid"
            if "createCICDScanPolicy" in query:
                self.created = variables
                sp = {"id": created_id, "name": "block-root"} if created_id else {}
                return {"createCICDScanPolicy": {"scanPolicy": sp}}, "tid"
            if "deleteCICDScanPolicy" in query:
                return {"deleteCICDScanPolicy": {"id": "pol-1"}}, "tid"
            return {}, "tid"
        return side

    def _exit(self, fn, argv, side):
        with mock.patch.dict(wz.os.environ, self.ENV, clear=True), \
             mock.patch.object(wz, "api", side_effect=side), self.assertRaises(SystemExit) as cm:
            fn(argv)
        return cm.exception.code

    def test_ensure_idempotent_when_present(self):
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "block-root"], self._api(existing=True)), 0)

    def test_ensure_creates_scoped_block_cli_policy(self):
        side = self._api(existing=False)
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "block-root"], side), 0)
        inp = self.created["input"]
        self.assertEqual(inp["policyLifecycleEnforcements"],
                         [{"enforcementMethod": "BLOCK", "deploymentLifecycle": "CLI"}])
        self.assertEqual(inp["iacParams"]["cloudConfigurationRules"], ["ctl-1"])
        self.assertEqual(inp["iacParams"]["severityThreshold"], "HIGH")
        self.assertFalse(inp["default"])

    def test_ensure_control_absent_is_environment_3(self):
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "b"], self._api(existing=False, control=[])), 3)

    def test_ensure_create_no_id_is_environment_3(self):
        side = self._api(existing=False, created_id=None)
        self.assertEqual(self._exit(wz.cmd_policy_ensure, ["--name", "b"], side), 3)

    def test_inspect_exists_absent_and_bad_require(self):
        self.assertEqual(self._exit(wz.cmd_policy_inspect, ["--name", "block-root"], self._api(existing=True)), 0)
        self.assertEqual(self._exit(wz.cmd_policy_inspect, ["--name", "block-root"], self._api(existing=False)), 1)
        self.assertEqual(self._exit(wz.cmd_policy_inspect, ["--name", "b", "--require", "x"], self._api(True)), 2)

    def test_delete_found_and_noop_when_absent(self):
        self.assertEqual(self._exit(wz.cmd_policy_delete, ["--name", "block-root"], self._api(existing=True)), 0)
        self.assertEqual(self._exit(wz.cmd_policy_delete, ["--name", "block-root"], self._api(existing=False)), 0)

    def test_missing_name_is_invocation_error_2(self):
        self.assertEqual(self._exit(wz.cmd_policy_inspect, [], self._api(existing=True)), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
