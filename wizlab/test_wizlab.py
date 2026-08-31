#!/usr/bin/env python3
# Stdlib-only harness (no external deps, matching wizlab). Locks the load-bearing invariants so
# refactors are safe without re-playing a lab: the 0/1/2/3 exit-code contract, IAM-trust parsing
# breadth, flag edges, and the main() dispatch guard. Run: python wizlab/test_wizlab.py
import io
import json
import pathlib
import types
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
        with mock.patch.object(wz.urllib.request, "urlopen", op), mock.patch.object(wz.time, "sleep"):
            with self.assertRaises(SystemExit) as cm:
                wz._post("https://x/", "d", {}, attempts=3)
        self.assertEqual(cm.exception.code, 3)
        self.assertEqual(op.call_count, 3)  # retried, not one-shot

    def test_post_4xx_fails_fast(self):
        err = urllib.error.HTTPError("u", 400, "bad", None, io.BytesIO(b"nope"))
        op = mock.MagicMock(side_effect=err)
        with mock.patch.object(wz.urllib.request, "urlopen", op), mock.patch.object(wz.time, "sleep"):
            with self.assertRaises(SystemExit) as cm:
                wz._post("https://x/", "d", {}, attempts=3)
        self.assertEqual(cm.exception.code, 3)
        self.assertEqual(op.call_count, 1)  # 4xx is not transient — no retry

    def test_main_bad_verb_is_invocation_error(self):
        with mock.patch.object(wz.sys, "argv", ["wizlab", "bogus", "verb"]):
            with self.assertRaises(SystemExit) as cm:
                wz.main()
        self.assertEqual(cm.exception.code, 2)

    def test_main_guards_uncaught_exception_as_2(self):
        boom = mock.MagicMock(side_effect=RuntimeError("kaboom"))
        with mock.patch.dict(wz.VERBS, {("session", "verify"): boom}):
            with mock.patch.object(wz.sys, "argv", ["wizlab", "session", "verify"]):
                with self.assertRaises(SystemExit) as cm:
                    wz.main()
        self.assertEqual(cm.exception.code, 2)  # bug, not a raw traceback exiting 1


class RoleInspectGrading(unittest.TestCase):
    DELEGATOR = "arn:aws:iam::851725410668:role/prod-us100-AssumeRoleDelegator"
    TID = "6ca852a0-af83-4f2d-9da9-f2f3bd1d23a3"

    def _run(self, aws_proc, delegator=DELEGATOR, tid=TID):
        with mock.patch.object(wz, "_aws", return_value=aws_proc), \
             mock.patch.object(wz, "_wiz_delegator", return_value=(delegator, tid)):
            with self.assertRaises(SystemExit) as cm:
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


class Naming(unittest.TestCase):
    def test_stem_is_session_scoped(self):
        self.assertEqual(wz._lab_stem("abc123"), "lab-abc123")

    def test_session_id_from_flag_then_env(self):
        self.assertEqual(wz._session_id(["--session", "flagid"]), "flagid")
        with mock.patch.dict(wz.os.environ, {"INSTRUQT_SESSION_ID": "envid"}, clear=False):
            self.assertEqual(wz._session_id([]), "envid")

    def test_session_id_missing_is_invocation_error(self):
        with mock.patch.dict(wz.os.environ, {}, clear=True):
            with self.assertRaises(SystemExit) as cm:
                wz._session_id([])
        self.assertEqual(cm.exception.code, 2)

    def test_user_email_keyed_on_session(self):
        self.assertEqual(wz._lab_user_email(["--session", "s1"])[0], "lab-s1@titra-labs.ai")


if __name__ == "__main__":
    unittest.main(verbosity=2)
