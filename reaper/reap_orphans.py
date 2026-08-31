#!/usr/bin/env python3
"""Out-of-band reaper. Per tenant: ask Instruqt labPlayReports for STOPPED lab sessions (tagged
tid:<tenant>), then reap each session's Wiz footprint + Keycloak user via wizlab, keyed on the
session id (objects are named lab-<session_id>). DRY-RUN by default; --commit deletes.

Stopped is Instruqt's own done-signal (immune to long/paused labs). The session id is the join:
it's the labPlayReports id AND the naming stem. No account, no Keycloak attributes, no age heuristic.

Env: INSTRUQT_TOKEN (API key); for --commit also WIZ_<TENANT>_CLIENT_ID/SECRET + LAB_KEYCLOAK_*.
"""
import json
import os
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime, timedelta

TEAM = os.getenv("INSTRUQT_TEAM", "wiz")
WINDOW_H = int(os.getenv("REAP_WINDOW_HOURS", "25"))  # rolling; re-runs are idempotent, so overlap is safe
# tenant key (the WIZ_TENANT value wizlab keys creds on) -> the lab's Instruqt tag. Extend as tenants onboard.
TENANTS = {"TBCMP": "tid:tbcmp"}


def _die(msg):
    print(f"reap_orphans: {msg}", file=sys.stderr)
    sys.exit(1)


def _instruqt(query, variables):
    tok = os.getenv("INSTRUQT_TOKEN") or _die("INSTRUQT_TOKEN not set")
    req = urllib.request.Request(
        "https://play.instruqt.com/graphql",
        data=json.dumps({"query": query, "variables": variables}).encode(),
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        res = json.loads(r.read())
    if res.get("errors"):
        _die(f"instruqt: {res['errors']}")
    return res["data"]


def stopped_sessions(tag):
    now = datetime.now(UTC)
    frm = (now - timedelta(hours=WINDOW_H)).strftime("%Y-%m-%dT%H:%M:%SZ")
    q = ("query($team:String!, $tag:String!, $from:Time!, $to:Time!) {"
         " labPlayReports(input:{teamSlug:$team, tags:[$tag],"
         " dateRangeFilter:{from:$from, to:$to}, pagination:{skip:0, take:500}})"
         " { items { id stoppedReason } } }")
    variables = {"team": TEAM, "tag": tag, "from": frm, "to": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    items = _instruqt(q, variables)["labPlayReports"]["items"]
    return [it["id"] for it in items if it.get("stoppedReason")]


def _wizlab(tenant, *args):
    r = subprocess.run(["wizlab", *args], env={**os.environ, "WIZ_TENANT": tenant},
                       capture_output=True, text=True, check=False)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


def main():
    commit = "--commit" in sys.argv
    total = 0
    for tenant, tag in TENANTS.items():
        sids = stopped_sessions(tag)
        print(f"# tenant {tenant} ({tag}): {len(sids)} stopped session(s) in last {WINDOW_H}h")
        for sid in sids:
            total += 1
            if not commit:
                print(f"DRY-RUN {tenant}: reap lab-{sid}* + delete lab-{sid}@")
                continue
            # Footprint first, user last: a crash leaves the user for the next run to retry.
            _wizlab(tenant, "user", "reap", "--session", sid, "--commit")
            _wizlab(tenant, "user", "delete", "--session", sid)
    print(f"# {total} session(s) {'reaped' if commit else 'to reap (dry-run)'}", file=sys.stderr)


if __name__ == "__main__":
    main()
