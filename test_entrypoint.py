#!/usr/bin/env python3
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent


class GcpCredentialFile(unittest.TestCase):
    def test_failed_login_still_removes_mode_600_key_file(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            capture = tmp / "capture"
            gcloud = tmp / "gcloud"
            gcloud.write_text(
                "#!/bin/sh\n"
                "case $1 in\n"
                "  auth) key=${4#--key-file}; stat -c '%a %n' \"$key\" > \"$CAPTURE\"; exit 1 ;;\n"
                "  *) exit 0 ;;\n"
                "esac\n"
            )
            gcloud.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{tmp}:{os.environ['PATH']}",
                "CAPTURE": str(capture),
                "GOOGLE_CREDENTIALS": '{"private_key":"secret"}',
            }
            result = subprocess.run(["/bin/sh", str(ROOT / "entrypoint.sh"), "true"], env=env,
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            mode, key = capture.read_text().strip().split(" ", 1)
            self.assertEqual(mode, "600")
            self.assertFalse(pathlib.Path(key).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
