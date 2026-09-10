"""The operator's dev-access path to a grader over the tailnet."""
import base64
import contextlib
import datetime
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

from . import core

# --- lease: the operator's dev-access path to a grader over the tailnet. Authoring-side only — both
# tokens below live on the operator, never in a lab, so in a grader every verb here exits 3.
TS_API = "https://api.tailscale.com/api/v2"


IQ_API = "https://play.instruqt.com/graphql"


IQ_TEAM = os.getenv("INSTRUQT_TEAM", "wiz")


# '-' resolves to the token's own default tailnet, so no tailnet name is pinned per operator.
_TS_TAILNET = "-"


# Marks a key this tool minted, so a crashed run's orphan is findable and revocable.
_LEASE_KEY_PREFIX = "dev-"


_TSKEY_RE = re.compile(r"tskey-[A-Za-z0-9-]+")


# A node lingers this long after its play ends, and the devices API exposes no `online` field, so
# freshness is the ONLY liveness signal — ordering by lastSeen alone returns dead nodes.
_NODE_FRESH_S = 90


def _scrub(text):
    """`tailscale up` echoes --authkey into its own error output, which lands in a setup log anyone
    running the lab can read — the exact standing leak per-run minting exists to avoid."""
    return _TSKEY_RE.sub("tskey-***REDACTED***", text or "")


def _ts(method, path, body=None, tolerate=None):
    """`tolerate` is an HTTP status that is an expected answer (a key already gone), returned as None."""
    tok = os.getenv("TAILSCALE_API_KEY") or core.die(3, "TAILSCALE_API_KEY not in environment")
    req = urllib.request.Request(
        TS_API + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            txt = r.read().decode()
            return json.loads(txt) if txt.strip() else {}
    except urllib.error.HTTPError as e:
        if e.code == tolerate:
            return None
        core.die(3, f"tailscale HTTP {e.code}: {_scrub(e.read().decode(errors='replace'))[:300]}")
    except Exception as e:
        core.die(3, f"tailscale unreachable: {type(e).__name__}: {e}")


def _iq(query, variables, tolerate=None):
    """`tolerate` names an error code that is an expected answer, not a fault — a missing secret after
    a clean teardown. Returns None so the caller reports the absence instead of dying on it."""
    tok = os.getenv("INSTRUQT_API") or core.die(3, "INSTRUQT_API not in environment")
    res = core._post(IQ_API, {"query": query, "variables": variables},
                {"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
                attempts=core._submissions(query))
    errs = res.get("errors")
    if errs:
        if tolerate and all(tolerate in json.dumps(e) for e in errs):
            return None
        core.die(3, f"instruqt: {_scrub(json.dumps(errs))[:300]}")
    return res.get("data") or {}


def _lease_stem(args):
    """The suffix both team-store names carry. Per lab, not per run: 2.0's `startLab` takes no
    `runtimeParameters`, so nothing can rebind a declared secret at start — the name is pinned in HCL
    at import and only its VALUE can rotate."""
    lab = core._flag(args, "--lab") or core.die(2, "lease: --lab <lab-name> is required")
    stem = re.sub(r"[^A-Za-z0-9]+", "_", lab).upper().strip("_")
    return re.sub(r"^TE_", "", stem)


def _secret_names(args):
    """Both halves, because the entrypoint gates the tailnet on one and sshd on the other: either
    alone yields a node with no shell."""
    stem = _lease_stem(args)
    return "TS_AUTHKEY_" + stem, "TE_DEV_SSH_PUBKEY_" + stem


def _keypair_dir(args):
    lab = re.sub(r"[^A-Za-z0-9._-]+", "_", core._flag(args, "--lab") or "")
    return pathlib.Path(os.getenv("WIZLAB_LEASE_DIR") or
                        pathlib.Path.home() / ".cache" / "wizlab" / "lease") / lab


def _mint_keypair(args):
    """A fresh keypair per play, not a long-lived one in the team store: nothing to maintain, nothing
    for anyone to delete out from under a play, and no private half outliving the lease it opened.
    Returns the public line to publish. Key auth is NOT decorative — grader and learner containers
    share the lab network and stock sshd binds 0.0.0.0, so this is what keeps a learner's terminal off
    the container holding every operator secret."""
    d = _keypair_dir(args)
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    priv = d / "id_ed25519"
    for stale in (priv, priv.with_suffix(".pub")):
        stale.unlink(missing_ok=True)
    try:
        r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                            f"wizlab-lease-{core._flag(args, '--lab')}", "-f", str(priv)],
                           capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        core.die(3, f"cannot run ssh-keygen: {type(e).__name__}: {e}")
    if r.returncode != 0:
        core.die(3, f"ssh-keygen exit {r.returncode}: {r.stderr.strip()[:200]}")
    priv.chmod(0o600)
    return priv, priv.with_suffix(".pub").read_text().strip()


def _upsert_secret(name, value, description):
    # The API stores the value verbatim and injects it decoded, so a raw value trips "illegal base64
    # data" at build — the lab sees a broken secret, not a wrong one.
    _iq("mutation($t: String!, $n: String!, $s: String!, $d: String!) "
        "{ upsertTeamSecret(teamSlug: $t, name: $n, secret: $s, description: $d) { name } }",
        {"t": IQ_TEAM, "n": name, "s": base64.b64encode(value.encode()).decode(), "d": description})


def _drop_secret(name):
    """True if there was a value to drop. Absent is the normal state after a clean teardown and reads
    False; any other failure raises, so `delete` never reports a drop that did not happen."""
    return _iq("mutation($t: String!, $n: String!) { deleteTeamSecret(teamSlug: $t, name: $n) }",
               {"t": IQ_TEAM, "n": name}, tolerate="BE_034_EntityNotFound") is not None


def _lease_keys():
    """`/keys` lists the tailnet's API ACCESS TOKENS alongside device auth keys, distinguishable only by
    `capabilities.devices.create` — absent on a token. Revoking the one `TAILSCALE_API_KEY` holds locks
    every lease verb out of the API and cannot be undone from here, so a key is swept only when it both
    carries the lease description AND proves it can create devices. The capability check is skipped when
    the list payload omits `capabilities` entirely (it is not always summarized), because the
    description prefix already excludes an operator token."""
    out = []
    for k in _ts("GET", f"/tailnet/{_TS_TAILNET}/keys").get("keys") or []:
        if not (k.get("description") or "").startswith(_LEASE_KEY_PREFIX):
            continue
        caps = k.get("capabilities")
        if caps is not None and not (caps.get("devices") or {}).get("create"):
            continue
        out.append(k)
    return out


def _lease_desc(args):
    """The description every key this lab mints carries, ahead of its per-key tag."""
    return f"{_LEASE_KEY_PREFIX}{(core._flag(args, '--lab') or '').lower()}-"


def _owned_keys(lab_desc):
    """This lab's keys, matched on the WHOLE description — one rule, shared by ensure and delete, or the
    two disagree about what they own. A bare prefix test also matches a longer lab name:
    `dev-te-dev-aws-` prefixes `dev-te-dev-aws-extra-<tag>`, which revokes another lab's live key
    mid-play and, on the delete path, revokes it INSTEAD of this lab's while reporting success."""
    own = re.compile(re.escape(lab_desc) + r"[0-9a-f]{8}\Z")  # the tag _mint_authkey generates
    return [k for k in _lease_keys() if own.match(k.get("description") or "")]


def _revoke(key_id):
    """A key is consumed at join, so revoking after a node is up does not drop it — it only closes the
    window the secret is usable. Already gone (404) is success; anything else raises, because a
    swallowed failure once left a live key behind a summary line that read "revoked"."""
    if key_id:
        _ts("DELETE", f"/tailnet/{_TS_TAILNET}/keys/{key_id}", tolerate=404)


def _fresh_nodes(match):
    now = datetime.datetime.now(datetime.UTC)
    out = []
    for d in _ts("GET", f"/tailnet/{_TS_TAILNET}/devices").get("devices") or []:
        seen_at = d.get("lastSeen")
        if not seen_at or match not in (d.get("hostname") or ""):
            continue
        age = (now - datetime.datetime.fromisoformat(seen_at)).total_seconds()
        if age <= _NODE_FRESH_S:
            out.append((age, (d.get("addresses") or [""])[0], d["hostname"]))
    return sorted(out)


def _backend_state():
    """`tailscale status` is the only local answer — the devices API cannot say which node is us."""
    try:
        st = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True,
                            timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        core.die(3, f"cannot run `tailscale status`: {type(e).__name__}: {e}")
    if st.returncode != 0:
        core.die(3, f"tailscale status exit {st.returncode}: {_scrub(st.stderr).strip()[:200]}")
    return (json.loads(st.stdout or "{}").get("BackendState") or "").lower()


def _self_on_tailnet():
    """This host, not any host: a minted key the operator cannot follow the grader over reaches
    nothing."""
    state = _backend_state()
    if state != "running":
        core.die(3, f"this host's tailscale is {state or 'unknown'}, not running; `lease ensure` joins it")


def _self_join(args, key):
    """Join THIS host on the same key the grader gets — what `reusable` is for. The key arrives as a
    file path, never argv: `/proc/<pid>/cmdline` is world-readable and `tailscale up` echoes the flag
    into its own error output. A host already Running is left alone, since re-upping churns a durable
    node identity for nothing. Failure is a warning, not an exit: the lease is already real, and
    `verify` is what refuses to grade over a tunnel that is not there."""
    if _backend_state() == "running":
        return "already on the tailnet"
    d = _keypair_dir(args)
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    kf = d / "authkey"
    kf.write_text(key)
    kf.chmod(0o600)
    try:
        r = subprocess.run(["sudo", "-n", "tailscale", "up", f"--auth-key=file:{kf}"],
                           capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return f"NOT joined ({type(e).__name__}); run: sudo tailscale up --auth-key=file:{kf}"
    if r.returncode != 0:
        return (f"NOT joined ({_scrub(r.stderr).strip()[:100]}); "
                f"run: sudo tailscale up --auth-key=file:{kf}")
    kf.unlink(missing_ok=True)
    return "joined this host to the tailnet"


def cmd_lease_verify(args):
    """Env health for the dev path. Exit 3 names the missing piece, so an unreachable grader never
    grades as a broken lab — the validator remaps 3 to INCONCLUSIVE."""
    for var in ("TAILSCALE_API_KEY", "INSTRUQT_API"):
        if not os.getenv(var):
            core.die(3, f"{var} not in environment; the dev path needs it (it lives on the operator, not a grader)")
    # Both tokens are spent, not just read: a present-but-revoked one passes every local check and then
    # fails at mint, which is a burnt play. This is the only place that failure is cheap.
    _ts("GET", f"/tailnet/{_TS_TAILNET}/keys")
    _iq("query($t: String!) { teamSecrets(teamSlug: $t) { name } }", {"t": IQ_TEAM})
    if "--no-self" not in args:
        _self_on_tailnet()
    print(f"ok: dev path ready (tailnet + instruqt team {IQ_TEAM})")


def _mint_authkey(args, lab_desc, ttl):
    """Ephemeral so the node self-deregisters at teardown, reusable so operator and grader can both
    join on it, preauthorized so no console click gates the join. NOT revoked at the end of `ensure`:
    the grader joins minutes later during setup, so it must stay valid until it expires with the
    lease."""
    for k in _owned_keys(lab_desc):
        _revoke(k["id"])
    desc = f"{lab_desc}{secrets.token_hex(4)}"  # 8 hex chars — _owned_keys matches on exactly that
    res = _ts("POST", f"/tailnet/{_TS_TAILNET}/keys", {
        "capabilities": {"devices": {"create": {"reusable": True, "ephemeral": True, "preauthorized": True}}},
        "expirySeconds": ttl,
        "description": desc,
    })
    if not res.get("id") or not res.get("key"):
        core.die(3, "tailscale returned no key")
    return res["id"], res["key"], desc


def cmd_lease_ensure(args):
    """Provision both halves of dev access for this lab's next play: a throwaway tailnet key and a
    throwaway ssh keypair. Either alone is useless — the entrypoint gates the tailnet on the key and
    sshd on the pubkey — so a partial push rolls back rather than burning a play."""
    ts_name, pub_name = _secret_names(args)
    ttl = int(core._flag(args, "--timelimit-seconds") or 0) + 3600
    lab_desc = _lease_desc(args)
    priv, pub = _mint_keypair(args)
    key_id, key, desc = _mint_authkey(args, lab_desc, ttl)
    try:
        _upsert_secret(ts_name, key, f"wizlab per-play tailnet key ({desc})")
        _upsert_secret(pub_name, pub, f"wizlab per-play dev ssh pubkey ({desc})")
    except core.WizlabError:
        # A live key nothing references is the worst outcome; a half-pushed pair burns the play. The
        # rollback is best-effort — the push failure is the one to report.
        with contextlib.suppress(core.WizlabError):
            _revoke(key_id)
        for n in (ts_name, pub_name):
            with contextlib.suppress(core.WizlabError):
                _drop_secret(n)
        raise
    joined = _self_join(args, key)
    print(f"LEASE_KEY_ID={key_id}\nLEASE_SECRET={ts_name}\nLEASE_SSH_KEY={priv}")
    print(f"rotated {ts_name} + {pub_name}; {joined}; start the play now (expires in {ttl}s)",
          file=sys.stderr)


def cmd_lease_inspect(args):
    """Resolve this session's grader over the tailnet (--require reachable), emitting GRADER_IP and
    the private key that opens it. Exit 1 = not up yet, which is a wait, not a failure. Two fresh nodes
    on one substring is exit 3 naming both: the freshest is a guess, and a guess hands the validator
    another play's grader with this play's key, which reads as every check broken."""
    require = core._flag(args, "--require") or "reachable"
    if require != "reachable":
        core.die(2, f"--require must be reachable, got {require}")
    _lease_stem(args)  # --lab is what locates the keypair, so it is required here too
    match = core._flag(args, "--hostname") or core._flag(args, "--session") or core.die(
        2, "lease inspect: --hostname <substring> or --session <id> is required")
    live = _fresh_nodes(match)
    if not live:
        print(f"no node matching {match!r} seen in the last {_NODE_FRESH_S}s")
        sys.exit(1)
    if len(live) > 1:
        core.die(3, f"{len(live)} nodes match {match!r}: {', '.join(h for _, _, h in live)}; narrow --hostname")
    age, addr, host = live[0]
    priv = _keypair_dir(args) / "id_ed25519"
    if not priv.exists():
        # `reachable` promises usable ssh, not node freshness: without the key the next step fails anyway.
        core.die(3, f"{host} is up but {priv} is missing; `lease ensure --lab` mints it before the play")
    print(f"GRADER_IP={addr}")
    print(f"LEASE_SSH_KEY={priv}")
    print(f"{host} seen {int(age)}s ago", file=sys.stderr)


def cmd_lease_delete(args):
    """Revoke the key, THEN drop the secrets and the private half. A crash in that order strands a
    dead string the next ensure overwrites; the reverse strands a live key with nothing pointing at
    it. Idempotent — a second run on an already-clean lab still exits 0. Safe the moment a verdict
    lands: revoking an auth key does not log out a node it already authorized, so this host stays
    `Running` (reproducer: `wizlab lease delete --lab L; tailscale status --json` → `BackendState:
    Running`). The ephemeral flag, not the revoke, is what reaps the grader's node."""
    ts_name, pub_name = _secret_names(args)
    key_id = core._flag(args, "--key-id")
    # Every key this lab owns, not the last one a prefix happened to match: teardown that leaves one
    # live key behind leaves a usable way onto the tailnet.
    key_ids = [key_id] if key_id else [k["id"] for k in _owned_keys(_lease_desc(args))]
    for k in key_ids:
        try:
            _revoke(k)
        except core.WizlabError as e:
            # Stop before the secrets: dropping them now strands a live key nothing points at.
            core.die(3, f"key {k} not revoked ({e}); secrets and the private key are kept, re-run to retry")
    dropped = []
    for n in (ts_name, pub_name):
        try:
            if _drop_secret(n):
                dropped.append(n)
        except core.WizlabError as e:
            core.die(3, f"{n} not dropped ({e}); {', '.join(key_ids) or 'no key'} revoked, re-run to retry")
    d = _keypair_dir(args)
    priv = d / "id_ed25519"
    for f in (priv, priv.with_suffix(".pub"), d / "authkey"):
        f.unlink(missing_ok=True)
    print(f"revoked {', '.join(key_ids) or '(no key)'}; dropped {', '.join(dropped) or '(no secrets)'}")
