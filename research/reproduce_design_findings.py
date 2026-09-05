#!/usr/bin/env python3
"""Snapshot observations for the OPEN findings in design-review.md; not regression expectations.

Run from any directory: `python3 research/reproduce_design_findings.py`. Exit 0 means the open
findings still reproduce. Network and subprocess execution are blocked; all resource operations use
mocks. Each observation retires from this file when its fix lands and `wizlab/test_wizlab.py` asserts
the corrected behavior instead — a probe here asserts today's defect, so it goes red on a fix.
"""

import contextlib
import importlib.util
import io
import pathlib
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

    def test_f8_lease_delete_reports_revocation_despite_api_failures(self):
        with mock.patch.object(wz, "_ts", side_effect=SystemExit(3)), \
             mock.patch.object(wz, "_iq", side_effect=SystemExit(3)), \
             mock.patch.object(wz.pathlib.Path, "unlink") as unlink, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.exit_code(wz.cmd_lease_delete, ["--lab", "te-dev-aws", "--key-id", "known-key"])
        self.assertEqual(result, 0)
        self.assertIn("revoked known-key", output.getvalue())
        self.assertEqual(unlink.call_count, 3)

    def test_d3_existing_sensor_credential_returns_no_output(self):
        with mock.patch.object(wz, "_find_sa", return_value={"id": "sa1"}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.exit_code(wz.cmd_sensor_ensure, ["--name", "lab-s1-sensor"])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "")

    def test_d3_existing_policy_ignores_requested_threshold(self):
        with mock.patch.object(wz, "_find_policy", return_value={"id": "policy1", "name": "fixture"}), \
             mock.patch.object(wz, "api") as api:
            result = self.exit_code(wz.cmd_policy_ensure, ["--name", "fixture", "--count-threshold", "2"])
        self.assertEqual(result, 0)
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
