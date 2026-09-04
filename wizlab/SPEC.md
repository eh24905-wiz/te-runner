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
Runtime-Sensor labs `sensor` and `detection`, and for Wiz Code labs `serviceaccount` and `code-scan`:
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
- `serviceaccount ensure|inspect|delete` — an on-the-fly `type:CLI` service account, the credential
  `wizcli auth` uses. `ensure` mints it named `<stem>-cli` with scopes `create:security_scans` +
  `read:scan_policies` (`--scopes` overrides), emits `WIZ_CLIENT_ID/WIZ_CLIENT_SECRET` (wizcli's own
  env names) to stdout + `$EXEC_OUTPUT`, idempotent by name (secret shown once). `inspect --require
  exists`; `delete` by `--id` or name. Shares one `createServiceAccount`/`deleteServiceAccount` path
  with `sensor` (parameterized over type + scopes); the reaper's ServiceAccount sweep also covers it.
- `code-scan inspect --require published|pass` — asserts a Wiz Code CI/CD scan for this session,
  scoped by the `session` tag (`--tag-key`/`--tag-value`, default value the session stem), latest scan
  wins. `published` = ≥1 scan exists; `pass` = latest `status.verdict == PASSED_BY_POLICY`
  (`FAILED_BY_POLICY` exits 1 at once). Grades the TENANT verdict, not the CLI exit code, because
  `WARN_BY_POLICY` exits 0 — only a blocking policy distinguishes a finding from a pass. Polls every
  `--interval` to `--timeout` (default 180s) since publish latency is unmeasured.

## What may be added
A change qualifies only if ALL hold:
1. **General** — reused across labs, not bespoke to one scenario.
2. **API-level** — a Wiz or CSP read/assert/mutation (`api()` / `_aws`).
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
