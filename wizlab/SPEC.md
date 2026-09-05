# wizlab spec

wizlab is the lab runtime. It owns every Wiz and CSP **API** fact, check, and mutation; labs are thin
wrappers (one `wizlab` call + an exit-code remap). Change it only within this contract.

## Grammar
`wizlab <noun> <verb>`.

| verb | means |
|---|---|
| inspect | read + assert, exit 0/1 (learner checks) |
| ensure | idempotent converge — create OR correct to the desired state (solves, setup) |
| delete | remove one resource (reapers) |
| verify | env/session health (check 1) |
| reap | audit + prefix cleanup of a session's footprint |
| tenant | (`wiz`) emit live tenant connector facts as `KEY=value` (+ `$EXEC_OUTPUT`) for a script/terraform; grow by adding keys, never removing |

Exit codes: 0 satisfied · 1 not · 2 invocation error · 3 environment error. Learner checks remap 2/3→1.

## Nouns
`session`, `connector`, `role`, `instance`, `user`, `wiz`, `audit`, `outpost`, for connectorless
Runtime-Sensor labs `sensor` and `detection`, for Wiz Code labs `serviceaccount` and `code-scan`, and
authoring-side `lease`:
- `outpost ensure|delete|inspect` — a Wiz Outpost (Automated deploy in the customer account). `ensure`
  createsOutpost named on the session stem, given `--role-arn` (the orchestrator TF module output Wiz
  assumes); `inspect --require exists|initialized|connected` asserts the `OutpostStatus` enum and
  `--require scanned` counts workload scans performed BY this Outpost (`resourceScanMetricsTrend`,
  `--lookback-days` default 2); `delete` reaps by name as uninstall → poll to UNINSTALLED → delete
  (`--timeout`, default 600s), exit 0 on a stuck record. Scoping key: the Outpost name == the session
  stem (`OutpostFilters` has no account/region field, same as the sensor plane). Three statuses that
  read as success are not: **INITIALIZED proves only that the object is registered**, **CONNECTED does
  not imply it scanned anything** (4 of 7 live ones had scanned nothing), and a direct delete fails.
  All measured — grade and reap off `measurements.yaml outpost_lifecycle.aws`, never off the status
  name's plain meaning.
- `connector ensure|inspect|delete` — a Cloud Connector. AWS `ensure` sets
  `authParams.customerRoleARN`; `--outpost-id`, or `--outpost-name` (default: the session stem, the name
  the console dropdown shows), with `--scanner-role-arn` also sets `authParams.outpostId` and
  `authParams.diskAnalyzer.scanner.roleARN` — the second phase of an Outpost deploy, without which Wiz
  builds no scan cluster. `inspect --require exists|healthy|outpost-bound`.
- `sensor ensure|delete|inspect` — a `type:SENSOR` service account is the sensor's credential
  (`ensure` mints it named on the session stem, emits `WIZ_API_CLIENT_ID/SECRET`; `delete` removes it;
  the reaper's ServiceAccount sweep also covers it). `inspect --require active` asserts the sensor
  named for the session reports `ACTIVE`. Scoping key: the installed sensor's name == the host name,
  which a lab pins to the session stem (neither `SensorFilters` nor `DetectionFilters` has a
  cloud-account/instance field).
- `detection inspect --rule-name N [--match-only]` — asserts ≥1 detection, keyed on
  `matchedRuleName` + `type` + the resolved `sensorId`. Never a rule id (tenant-specific) and never an
  Issue/Threat object (tenant-wide anti-burst cap). Default type `GENERATED_THREAT`; `--match-only`
  queries the sibling that matched and raised no threat.
- `serviceaccount ensure|inspect|delete` — the on-the-fly credential `wizcli auth` uses, minted via a
  CLI DEPLOYMENT (`createCliDeployment`), NOT `createServiceAccount`: `type:CLI` accounts are internal
  and that mutation rejects them. `ensure` names it `<stem>-cli` and converges to one fresh deployment
  (delete-then-mint, since the secret is shown once), emitting `WIZ_CLIENT_ID` (the deployment SA's
  `clientId`) + `WIZ_CLIENT_SECRET` (the payload's `clientSecret`) to stdout + `$EXEC_OUTPUT`.
  `inspect --require exists` and `delete` (by `--id` or name) go through `deployments(type:WIZ_CLI)` /
  `deleteCliDeployment`. The deployment's SA is named `<stem>-cli-deployment-<uuid>`, so the reaper's
  `ServiceAccount` `lab-<id>*` sweep also catches it. The `sensor` path stays on
  `createServiceAccount(type:SENSOR)`, unchanged.
- `lease verify|ensure|inspect|delete --lab N` — the operator's dev-access path to a grader over the
  tailnet. Authoring-side: reads `TAILSCALE_API_KEY` + `INSTRUQT_API` from the operator, never from a
  lab, so in a grader it is inert. `verify` asserts both tokens, Instruqt reachability, and this
  host's own tailnet membership (`tailscale status` → `BackendState`, the only local answer) — the
  precheck that stops an unreachable grader from grading as a broken lab. `ensure` provisions **both**
  halves of dev access, fresh per play: one ephemeral, reusable, preauthorized tailnet key
  (`expirySeconds` = the lab's `timelimit` + 3600) under `TS_AUTHKEY_<LAB>`, and an ed25519 keypair
  whose public half goes under `TE_DEV_SSH_PUBKEY_<LAB>`, private half left in
  `~/.cache/wizlab/lease/<lab>/`. Both values **base64** (a raw one errors `illegal base64 data`);
  both names per-lab, because 2.0's `startLab` takes no `runtimeParameters` to bind a per-run name
  (`te-labkit-v2/authoring/instruqt-2.0.md`). This lab's prior key is revoked first — that bounds live
  keys to one per lab and kills a crashed run's orphan, the only orphan nameable without guessing
  which play a key belongs to — and a failed upsert rolls the whole set back, since a live key with
  no reference is worse than no key. Key auth is not optional and the tailnet is not the perimeter:
  grader and learner containers share `resource.network.lab` and stock sshd binds `0.0.0.0`
  (`PermitRootLogin prohibit-password`), so the pubkey is the only thing keeping a learner terminal
  off the container holding every operator secret. `inspect --require reachable` resolves the
  session's node by `lastSeen` freshness — the devices API exposes no `online` field and an ephemeral
  node lingers ~30 min past its play — and emits `GRADER_IP` + `LEASE_SSH_KEY`. `delete` revokes by
  key id, THEN drops both secrets and the private key: a crash that order strands a dead string, the
  reverse strands a live key. Between plays the team store holds no dev credential at all, so a lab
  shipped with the dev block live references names that do not exist.
- `policy ensure|inspect|delete --name N` — the BLOCK CI/CD IaC scan policy a code-scan gate needs.
  `ensure` is idempotent by name; absent, it creates a `type:IAC` policy with `enforcementMethod
  BLOCK` on `deploymentLifecycle CLI`, scoped (`iacParams.cloudConfigurationRules`) to the builtin
  Dockerfile control 'Last User Is root' (resolved live via `cloudConfigurationRules`, never
  hard-coded; `--rule-id`/`--severity`/`--count-threshold` override), `default:false` so only a
  `wizcli --policies <name>` scan is gated. `inspect --require exists` verifies setup; `delete`
  removes it. A SHARED, PERSISTENT fixture — the reaper never touches it (not session-scoped).
- `code-scan inspect --require published|pass` — asserts a Wiz Code CI/CD scan for this session,
  scoped by the `session` tag (`--tag-key`/`--tag-value`, default value the session stem), latest scan
  wins. `published` = ≥1 scan exists; `pass` = latest `status.verdict == PASSED_BY_POLICY`
  (`FAILED_BY_POLICY` exits 1 at once). Grades the TENANT verdict, not the CLI exit code, because
  `WARN_BY_POLICY` exits 0 — only a blocking policy distinguishes a finding from a pass. Polls every
  `--interval` to `--timeout` (default 180s) since publish latency is unmeasured.

## What may be added
A change qualifies only if ALL hold:
1. **General** — reused across labs, not bespoke to one scenario.
2. **API-level** — a Wiz or CSP read/assert/mutation (`api()` / `_aws`), or a Tailscale/Instruqt one
   the lab runtime itself depends on (`lease`). Not a third cloud: the bar is an API no lab may hold
   credentials for.
3. **Fits the grammar** — a noun + one of the verbs above, at that verb's meaning.

## What may NOT
- A verb or flag per scenario or per assertion — compose existing verbs instead.
- Config-field assertions bolted onto `inspect --require` (which asserts lifecycle *state*); lean on
  the system's own signal (e.g. CONNECTED) or read a general field in the check. Carve-out only where no
  lifecycle state separates the cases: an Outpost-unbound connector still reaches CONNECTED while its
  Outpost holds INITIALIZED with `errorCode` null, so `--require outpost-bound` reads `outpost.id`.
- CSP **infrastructure** provisioning (VPCs, instances) — that is Terraform
  (`te-labkit-v2/template/infra/<csp>/`), not wizlab.
- Anything a lab can already do by composing existing verbs.

## Change process
Propose → **operator approves** → update this spec → then implement. Default answer is no; the bar is
general + API-level + fits the grammar. Gates: `ruff` + `xenon` + `test_wizlab.py` (CI); cite
`measurements.yaml`, never re-derive it. Tests lock the exit-code contract + IAM parsing — a refactor
that stays green needs no lab re-play.
