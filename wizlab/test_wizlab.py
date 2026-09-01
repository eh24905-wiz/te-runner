#!/usr/bin/env python3
# Stdlib-only harness (no external deps, matching wizlab). Locks the load-bearing invariants so
# refactors are safe without re-playing a lab: the 0/1/2/3 exit-code contract, IAM-trust parsing
# breadth, flag edges, and the main() dispatch guard. Run: python wizlab/test_wizlab.py
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
        # "learner wrong" (the v1 LIVENESS class).
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
            did, alert = wz._reap_one("tok", "dc", "CreateServiceAccount", "lab-s1-sa", True)
        self.assertFalse(did)
        self.assertIn("matched 2", alert)

    def test_kc_user_id_refuses_multiple_exact(self):
        dup = json.dumps([{"id": "1", "username": "lab-s1@titra-labs.ai"},
                          {"id": "2", "email": "lab-s1@titra-labs.ai"}])
        with mock.patch.object(wz, "_kc_call", return_value=(200, dup)), self.assertRaises(SystemExit) as cm:
            wz._kc_user_id("http://kc", "realm", "tok", "lab-s1@titra-labs.ai")
        self.assertEqual(cm.exception.code, 3)

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

    def test_unproven_paths_refuse_rather_than_guess(self):
        with self.assertRaises(SystemExit) as cm:
            wz.cmd_connector_ensure(["--cloud", "azure", "--account-id", "sub-1"])
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit) as cm:  # provisioning belongs to terraform, not wizlab
            wz.cmd_role_ensure(["--cloud", "gcp"])
        self.assertEqual(cm.exception.code, 2)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
