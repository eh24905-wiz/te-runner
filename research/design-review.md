# Design review — open findings

Findings distinguish reproduced local behavior from architectural recommendations. No live tenant mutation, image build, or deployed-image check backs any of them. F1, F2, F3, F5, F6, F9 and F10 are closed — `wizlab/test_wizlab.py` asserts the corrected behavior, so nothing here restates them; the numbering gap is deliberate. F7's cleanup-coverage decision is settled in `SPEC.md`. Reassess the rest against the working tree before implementing.

## Verifying the open findings

`python3 research/reproduce_design_findings.py` → exit 0, 4 observations. Each asserts today's defect, so it goes red on a fix and retires into `wizlab/test_wizlab.py` as a desired-behavior regression. Suites: `python3 wizlab/test_wizlab.py` (177), `python3 reaper/test_reap_orphans.py` (5), `python3 test_entrypoint.py` (1). Gates: `ruff check`, `xenon --max-absolute C --max-average B wizlab/wizlab`; average complexity B. Interpreters: CI 3.11, image 3.12. Passing mocked tests establishes no external API behavior.

## Patterns to preserve

| Pattern | Why it is useful; evidence |
|---|---|
| Thin lab wrappers and explicit CLI contract | Centralizes API facts and separates learner failure from environment failure; `SPEC.md`, `VERBS`, `die`. |
| Assertions use domain signals | `_scan_counts` distinguishes scanning from connectivity; `cmd_codescan_inspect` uses the published policy verdict. |
| Session identity and exact matching | `_lab_stem`, `_kc_user_id`, `_reap_find`, `_owned_keys` scope operations and refuse duplicates. |
| Measured facts with verification guidance | `measurements.yaml` distinguishes observations from guarantees and records how to recheck them. |
| Small reusable helpers | `_NODE`, `_cloud`, `_kc_session`, `_cli` consolidate real repetition without hiding provider differences. |

## F4 — Medium: resource searches cannot establish completeness

`_reap_find` takes 50 matches; `_reap_sweep_type` takes 100 without pagination metadata. Probe F4 supplies a full page: one query, no continuation, no blocking result. Similar limits occur in `_find_sa`, `_find_cli_deployment`, `_find_policy`, and connector/sensor/Outpost searches. Missing matches can become false absence; destructive uniqueness checks cover only the returned page. Add pagination where supported, or an explicit incomplete result that prevents destructive conclusions. Prioritize the lookups feeding a destructive uniqueness decision; elsewhere an incomplete result suffices. Acceptance: match or duplicate beyond the first page, repeated cursors, and a server ignoring pagination. Session-report pagination and audit-limit reporting are already fixed; preserve those.

## F8 — Medium: lease cleanup hides failed revocations

`_revoke` and `_drop_secret` suppress all `SystemExit`, including API authorization and transport failures. `cmd_lease_delete` then removes local files, prints “revoked”, and exits 0. Probe F8 confirms that result when both remote APIs fail. `_iq` already distinguishes expected missing-secret errors, so outer blanket suppression loses useful information. Exposure is bounded — an ephemeral key self-expires with the lease — so this is a truthfulness defect, not a standing credential. Return structured outcomes, tolerate confirmed absence, report failed revocation truthfully, and preserve enough nonsecret identity to retry. Acceptance: already-absent remains successful; denied or unavailable APIs produce an incomplete result and recovery instructions.

## D1 — Refactor along responsibilities, preserving deployment simplicity

The runtime has 34 command handlers. Size alone is not the problem: HTTP clients, parsing, assertions, cleanup policy, output publication, and operator lease lifecycle change for different reasons. Extract a small importable package behind the same executable: CLI boundary, provider clients, resource operations, pure assertions, cleanup orchestration, and operator lease support. Keep Terraform outside it and preserve stdlib-only runtime dependencies. Do not introduce a provider/plugin framework merely to reduce line count. Acceptance: same command/output/exit contracts, installable image layout, and independently testable helpers; `main` owns process exits rather than deep transport helpers terminating orchestration. Do this after D3 settles the postconditions it would freeze.

## D2 — Consolidate shared operational policy

`api`, `_gql`, `_kc_call`, `_ts`, `_iq`, and reaper `_instruqt` duplicate transport concerns with different failure semantics. Share timeout budgets, safe retry decisions, secret redaction, and typed transport errors while keeping provider response parsing explicit. A command-scoped Wiz client can reuse authentication instead of `token_and_dc` running for every API call; refresh only on a defined expiry/auth path. Centralize complete enumeration and exact/unique selection rather than repeating `next`, sorting, and partial-page assumptions. `_cli` needs bounded subprocess execution. Acceptance: failure classification, retry counts, and token reuse are tested through transport boundaries, including GraphQL partial-data responses. `_submissions` is the retry rule to share; a consolidated client must not reintroduce a resend a caller did not authorize.

## D3 — Define successful ensure and inspect precisely

`_ensure_sa` succeeds without credentials when a sensor account exists; `cmd_serviceaccount_ensure` instead deletes and recreates a CLI deployment. `cmd_policy_ensure` and `cmd_outpost_ensure` accept existing names without reconciling configuration. D3 probes confirm empty sensor output and ignored policy threshold changes. These may be intentional contracts, but “idempotent converge” alone does not explain them. Specify postconditions per resource, ownership, secret recovery/rotation, and interrupted-run behavior — these are also what reconciles an unknown mutation outcome, since `_submissions` now refuses the resend. For shared policies, report drift before mutating other labs' fixture. Also define whether `lease inspect --require reachable` promises node freshness or usable SSH: it currently accepts freshness even without a local private key.

## D4 — Test behavior across boundaries

The suite reaches 25 of 34 `cmd_*` bodies when traced with `sys.settrace`; this is handler reachability, not line/branch coverage. Cover the destructive and credential paths first — `cmd_connector_delete`, `cmd_user_delete`, `cmd_sensor_delete`, `cmd_user_login_url` — not an arbitrary coverage percentage. Convert accepted observations into tests for the corrected behavior; include partial remote success, duplicate identities, pagination boundaries, and repeated teardown. Preserve real temporary-file/key-generation checks. Green mocked tests do not justify skipping live validation when changing an API payload, provider semantics, or resource lifecycle; revisit that blanket claim in `SPEC.md`.

## D5 — Make releases validate the artifact they publish

`build.yml` publishes tags without depending on `lint.yml` or an image smoke test. The Dockerfile floats its base and several downloaded CLIs, including wizcli; a source tag alone does not make rebuilds reproducible. Gate publication on checks for the same commit, test Python 3.12, smoke-test installed binaries and entrypoint, record dependency versions, and use verified artifacts/digests where practical. `reap.yml` defaults manual commit to true despite its dry-run comment, and the repository variable can override an unchecked input; make mode precedence explicit and test it. The scheduled reaper pins image `v0.1.32` — update the pin when accepted runtime fixes ship.

## Next actions

| Order | Action and completion criterion |
|---|---|
| 1 | F8 structured revocation outcomes, no blanket suppression. |
| 2 | F4 pagination on the lookups feeding a destructive uniqueness decision. |
| 3 | Specify D3 postconditions; add D4 destructive/credential coverage. |
| 4 | Gate the release (D5), then extract shared boundaries (D1, D2). |

Open question: whether `actionParameters` carries the created object's id, not only its name. If it does, a direct id delete converts much of `unknown` into `removed` — the only change that shrinks uncovered residue rather than reclassifying it. Needs a live-tenant reproducer. `fr/reaper-safety-and-role-refactor` is superseded by PR #1; do not merge it.
