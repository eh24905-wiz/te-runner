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

## What may be added
A change qualifies only if ALL hold:
1. **General** — reused across labs, not bespoke to one scenario.
2. **API-level** — a Wiz or CSP read/assert/mutation (`api()` / `_aws`).
3. **Fits the grammar** — a noun + one of the verbs above, at that verb's meaning.

## What may NOT
- A verb or flag per scenario or per assertion — compose existing verbs instead.
- Config-field assertions bolted onto `inspect --require` (which asserts lifecycle *state*); lean on
  the system's own signal (e.g. CONNECTED) or read a general field in the check.
- CSP **infrastructure** provisioning (VPCs, instances) — that is Terraform
  (`te-labkit-v2/template/infra/<csp>/`), not wizlab.
- Anything a lab can already do by composing existing verbs.

## Change process
Propose → **operator approves** → update this spec → then implement. Default answer is no; the bar is
general + API-level + fits the grammar. Gates: `ruff` + `xenon` + `test_wizlab.py` (CI); cite
`measurements.yaml`, never re-derive it. Tests lock the exit-code contract + IAM parsing — a refactor
that stays green needs no lab re-play.
