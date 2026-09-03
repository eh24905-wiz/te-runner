#!/usr/bin/env python3
import io
import pathlib
import unittest
from importlib.machinery import SourceFileLoader
from unittest import mock

rp = SourceFileLoader(
    "reap_orphans", str(pathlib.Path(__file__).resolve().parent / "reap_orphans.py")
).load_module()


class SessionDiscovery(unittest.TestCase):
    def test_paginates_until_a_short_page(self):
        pages = [
            {"labPlayReports": {"items": [{"id": "a", "stoppedReason": "done"},
                                            {"id": "live", "stoppedReason": None}]}},
            {"labPlayReports": {"items": [{"id": "b", "stoppedReason": "timeout"}]}},
        ]
        with mock.patch.object(rp, "PAGE_SIZE", 2), \
             mock.patch.object(rp, "_instruqt", side_effect=pages) as api:
            self.assertEqual(rp.stopped_sessions("tid:x"), ["a", "b"])
        self.assertEqual([c.args[1]["skip"] for c in api.call_args_list], [0, 2])

    def test_refuses_to_page_forever_when_skip_is_ignored(self):
        full = {"labPlayReports": {"items": [{"id": "a", "stoppedReason": "done"}] * 2}}
        with mock.patch.object(rp, "PAGE_SIZE", 2), mock.patch.object(rp, "MAX_PAGES", 3), \
             mock.patch.object(rp, "_instruqt", return_value=full) as api, \
             self.assertRaises(SystemExit) as cm:
            rp.stopped_sessions("tid:x")
        self.assertEqual(api.call_count, 3)
        self.assertEqual(cm.exception.code, 1)


class ReapOrdering(unittest.TestCase):
    def test_failed_wiz_cleanup_retains_keycloak_user(self):
        with mock.patch.object(rp, "_wizlab", return_value=3) as wizlab:
            self.assertFalse(rp._reap_session("T", "s1", True))
        self.assertEqual(wizlab.call_count, 1)
        self.assertEqual(wizlab.call_args.args[1:3], ("user", "reap"))

    def test_successful_wiz_cleanup_deletes_user_second(self):
        with mock.patch.object(rp, "_wizlab", side_effect=[0, 0]) as wizlab:
            self.assertTrue(rp._reap_session("T", "s1", True))
        self.assertEqual([c.args[1:3] for c in wizlab.call_args_list], [("user", "reap"), ("user", "delete")])

    def test_main_exits_nonzero_and_names_the_sids_to_retry(self):
        # A retained user only self-heals inside WINDOW_H; past that the sid is the only way back in.
        with mock.patch.object(rp, "TENANTS", {}), \
             mock.patch.object(rp, "_reap_session", return_value=False), \
             mock.patch.dict(rp.os.environ, {"REAP_SESSIONS": "s1,s2"}, clear=True), \
             mock.patch.object(rp.sys, "argv", ["reap_orphans.py", "--commit"]), \
             mock.patch.object(rp.sys, "stderr", io.StringIO()) as err, \
             self.assertRaises(SystemExit) as cm:
            rp.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn('REAP_SESSIONS="s1,s2"', err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
