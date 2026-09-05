#!/usr/bin/env python3
"""Offline snapshot observations for design-review.md; not regression expectations for fixed code.

Run from any directory with Python 3.11+. Exit 0 means the documented observations still hold.
Network and subprocess execution are blocked; all resource operations use mocks.
"""

import contextlib
import importlib.util
import io
import pathlib
import types
import unittest
import urllib.error
from importlib.machinery import SourceFileLoader
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


wz = load("review_wizlab", ROOT / "wizlab/wizlab")
rp = load("review_reaper", ROOT / "reaper/reap_orphans.py")


class ReviewObservations(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(
            wz.urllib.request, "urlopen", side_effect=AssertionError("unexpected network access")))
        self.enterContext(mock.patch.object(
            wz.subprocess, "run", side_effect=AssertionError("unexpected subprocess execution")))
        self.enterContext(mock.patch.object(wz.time, "sleep"))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(contextlib.redirect_stderr(io.StringIO()))

    def exit_code(self, fn, *args):
        with self.assertRaises(SystemExit) as result:
            fn(*args)
        return result.exception.code

    def test_f1_http_503_retries_a_mutation_three_times(self):
        error = urllib.error.HTTPError(
            "https://test.invalid", 503, "unavailable", None, io.BytesIO(b"failure"))
        self.addCleanup(error.close)
        with mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid")), \
             mock.patch.object(wz.urllib.request, "urlopen", side_effect=error) as http:
            self.assertEqual(self.exit_code(wz.api, "mutation M { createConnector { id } }", {}), 3)
        self.assertEqual(http.call_count, 3)

    def test_f2_mismatched_iam_statements_pass(self):
        def statement(principal, external_id):
            return {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": external_id}}}

        delegator = "arn:aws:iam::111111111111:role/prod-us1-AssumeRoleDelegator"
        other = "arn:aws:iam::222222222222:role/Other"
        policy = {"Statement": [statement(delegator, "wrong-tenant"), statement(other, "expected-tenant")]}
        role = {"AssumeRolePolicyDocument": policy}
        with mock.patch.object(wz, "_wiz_delegator", return_value=(delegator, "expected-tenant")):
            self.assertEqual(self.exit_code(wz._inspect_aws_trust, "Role", role), 0)

    def test_f3_outpost_timeout_succeeds_without_a_sweep_handler(self):
        node = {"id": "outpost-1", "status": "UNINSTALLING"}
        with mock.patch.object(wz, "_resolve_outpost", return_value=node), \
             mock.patch.object(wz, "_await_uninstalled", return_value="UNINSTALLING"), \
             mock.patch.object(wz, "api") as api:
            self.assertEqual(self.exit_code(wz.cmd_outpost_delete, ["--name", "lab-s1", "--timeout", "1"]), 0)
        api.assert_not_called()
        self.assertNotIn("Outpost", wz._SWEEP_TYPES)
        self.assertNotIn("Outpost", wz._REAP_OVERRIDES)

    def test_f4_resource_sweep_stops_at_one_full_page(self):
        nodes = [{"id": str(i), "name": f"lab-s1-{i}"} for i in range(100)]
        data = {"reports": {"nodes": nodes}}
        with mock.patch.object(wz, "_gql", return_value=(data, [])) as gql:
            self.assertEqual(wz._reap_sweep_type("tok", "dc", "Report", "lab-s1", False), (100, 0, 0))
        self.assertEqual(gql.call_count, 1)
        self.assertNotIn("pageInfo", gql.call_args.args[2])

    def test_f5_missing_flag_value_consumes_commit(self):
        self.assertEqual(wz._flag(["--session", "--commit"], "--session"), "--commit")

    def test_f6_empty_gcp_account_list_passes_verification(self):
        proc = types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        with mock.patch.object(wz, "_gcp", return_value=proc), \
             mock.patch.dict(wz.os.environ, {"GOOGLE_CREDENTIALS": "{}", "GOOGLE_PROJECT": "project"}):
            self.assertIsNone(wz._verify_csp("gcp"))

    def test_f7_unknown_audit_type_is_nonblocking(self):
        with mock.patch.object(wz, "_reap_find", return_value=(None, None, "unknown field")):
            did, alert, blocked = wz._reap_one("tok", "dc", "CreateUnknownThing", "free-form-name", True)
        self.assertFalse(did)
        self.assertIsNotNone(alert)
        self.assertFalse(blocked)

    def test_d3_existing_sensor_credential_returns_no_output(self):
        with mock.patch.object(wz, "_find_sa", return_value={"id": "sa1"}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.exit_code(wz.cmd_sensor_ensure, ["--name", "lab-s1-sensor"])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "")

    def test_f8_lease_delete_reports_revocation_despite_api_failures(self):
        with mock.patch.object(wz, "_ts", side_effect=SystemExit(3)), \
             mock.patch.object(wz, "_iq", side_effect=SystemExit(3)), \
             mock.patch.object(wz.pathlib.Path, "unlink") as unlink, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.exit_code(wz.cmd_lease_delete, ["--lab", "te-dev-aws", "--key-id", "known-key"])
        self.assertEqual(result, 0)
        self.assertIn("revoked known-key", output.getvalue())
        self.assertEqual(unlink.call_count, 3)

    def test_f9_lease_key_prefix_also_revokes_another_lab(self):
        keys = [{"id": "own", "description": "dev-te-dev-aws-12345678"},
                {"id": "other", "description": "dev-te-dev-aws-extra-12345678"}]
        with mock.patch.object(wz, "_lease_keys", return_value=keys), \
             mock.patch.object(wz, "_revoke") as revoke, \
             mock.patch.object(wz, "_ts", return_value={"id": "new", "key": "synthetic-key"}):
            wz._mint_authkey([], "dev-te-dev-aws-", 3600)
        self.assertEqual([c.args[0] for c in revoke.call_args_list], ["own", "other"])

    def test_f10_missing_exact_control_selects_an_unrelated_control(self):
        unrelated = {"id": "other-control", "name": "Last User Is Something Else"}
        with mock.patch.object(wz, "api", return_value=({"cloudConfigurationRules": {"nodes": [unrelated]}}, "tid")):
            self.assertEqual(wz._resolve_dockerfile_control("Last User Is"), unrelated)

    def test_d3_existing_policy_ignores_requested_threshold(self):
        with mock.patch.object(wz, "_find_policy", return_value={"id": "policy1", "name": "fixture"}), \
             mock.patch.object(wz, "api") as api:
            result = self.exit_code(wz.cmd_policy_ensure, ["--name", "fixture", "--count-threshold", "2"])
        self.assertEqual(result, 0)
        api.assert_not_called()

    def test_resolved_failed_cleanup_retains_user(self):
        with mock.patch.object(rp, "_wizlab", return_value=3) as cli:
            self.assertFalse(rp._reap_session("TBCMP", "s1", True))
        self.assertEqual(cli.call_count, 1)
        self.assertEqual(cli.call_args.args[1:3], ("user", "reap"))

    def test_resolved_sweep_failures_block_committed_reap(self):
        with mock.patch.object(wz, "token_and_dc", return_value=("tok", "dc", "tid")), \
             mock.patch.object(wz, "_reap_enumerate", return_value=([], None)), \
             mock.patch.object(wz, "_reap_sweep_type", return_value=(0, 1, 1)):
            self.assertEqual(self.exit_code(wz.cmd_reap, ["--session", "s1", "--commit"]), 3)

    def test_resolved_keycloak_503_is_environment_failure(self):
        with mock.patch.object(wz, "_kc_session", return_value=("url", "realm", "tok", "email", "name")), \
             mock.patch.object(wz, "_kc_user_id", return_value="uid"), \
             mock.patch.object(wz, "_kc_call", return_value=(503, b"failure")):
            self.assertEqual(self.exit_code(wz.cmd_user_inspect, []), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
