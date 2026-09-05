# Project health and design review

Reviewed fetched `main` at [`dbffcec`](https://github.com/eh24905-wiz/te-runner/tree/dbffcecdd83b693bab8fa7ed417570cbd76470bb), September 5, 2026. This supersedes the assessment of `92be3e5`, which was 19 commits behind. Sources: [runtime](../wizlab/wizlab), [reaper](../reaper/reap_orphans.py), [entrypoint](../entrypoint.sh), [specification](../wizlab/SPEC.md), [tests](../wizlab/test_wizlab.py), and workflows linked below. Symbol names identify implementation evidence. Findings distinguish reproduced local behavior from architectural recommendations; no live tenant mutations, image build, or deployed-image verification were performed. New lease, policy, service-account, and code-scan paths are included in the static review. Reassess applicability against the target commit before implementing.

## Review the fr branch before planning work

`fr/reaper-safety-and-role-refactor` remains at `7726129`, but its hardening work is already incorporated, with additional changes, in [PR #1](https://github.com/eh24905-wiz/te-runner/pull/1), commit `739cba0`. Compare `git diff 7726129 739cba0 -- wizlab/wizlab reaper .github/workflows/lint.yml`; do not infer missing work from branch ancestry or merge the old branch wholesale. Review especially the intentional change from every alert blocking cleanup to separate `alerted` and `blocked` outcomes. AWS role inspection is also split into retrieval and assertion helpers; F2 remains applicable. The scheduled reaper pins `v0.1.32`, whose source tag resolves to `739cba0`; the deployed image contents were not independently checked.

## Findings already resolved on main

| Earlier concern | Current evidence |
|---|---|
| User deletion after failed cleanup; silent audit/sweep faults | `_reap_session` retains users; `_reap_enumerate` reports errors/limits; `_reap_sweep_type` blocks lookup failures. `ReapOrdering` tests sequencing; F7 covers an exception. |
| First 500 Instruqt reports only | `stopped_sessions` paginates, with `MAX_PAGES`; `SessionDiscovery` tests both cases. |
| Keycloak group HTTP failure grades learner wrong | `cmd_user_inspect` exits 3; `ExitCodeContract` tests it. |
| GCP temporary key left after failed login | Entrypoint uses a mode-600 temporary file; `GcpCredentialFile` verifies removal. |

## Verification and reproducing observations

Run `python research/reproduce_design_findings.py` from the repository root: expected exit 0, 15 observations matching this snapshot. The [script](reproduce_design_findings.py) blocks network and subprocess execution; F-numbered methods reproduce findings, `resolved` methods check corrected behavior. These are snapshot observations, not desired-behavior regression tests: after fixes, affected observations should fail until updated or retired. Production suites passed: `python wizlab/test_wizlab.py` (147), `python reaper/test_reap_orphans.py` (5), `python test_entrypoint.py` (1). Ruff and Xenon passed; Radon reports 127 runtime functions, average B (5.43). Local interpreter: Python 3.14.4; CI: 3.11; image: 3.12. Passing local tests does not establish external API behavior.

## Patterns to preserve

| Pattern | Why it is useful; evidence |
|---|---|
| Thin lab wrappers and explicit CLI contract | Centralizes API facts and separates learner failure from environment failure; `SPEC.md`, `VERBS`, `die`. |
| Assertions use domain signals | `_scan_counts` distinguishes scanning from connectivity; `cmd_codescan_inspect` uses the published policy verdict. |
| Session identity and exact matching | `_lab_stem`, `_kc_user_id`, `_reap_find` support scoped operations and duplicate refusal. F9 shows where consistency is missing. |
| Measured facts with verification guidance | `measurements.yaml` distinguishes observations from guarantees and records how to recheck them. |
| Small reusable helpers | `_NODE`, `_cloud`, `_kc_session`, `_cli` consolidate real repetition without hiding provider differences. |

## F1 — High: transport retries non-idempotent mutations

`api` suppresses GraphQL-level mutation retries, but `_post` retries HTTP 5xx, 429, and transport exceptions regardless of operation. Probe F1 records three mutation submissions after HTTP 503, then exit 3. If the server applied a request before its response failed, resubmission could duplicate resources. `TransientGraphqlErrors.test_a_mutation_is_never_retried` mocks `_post`, so it cannot catch this. Pass an explicit retry policy into transport; default unprotected mutations to one attempt, then reconcile uncertain outcomes using resource identity. Acceptance: reads retain bounded retries; mutation 503, timeout, and response-decoding failure cause one submission. HTTP retry semantics: https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2

## F2 — High: IAM checks combine unrelated statements

`_inspect_aws_trust` flattens principals and external IDs independently across allowed statements. Probe F2 passes a correct delegator with a wrong external ID in one statement, and the correct external ID for another principal in a second statement; exit is 0. Require the intended principal, action, and acceptable external-ID condition within the same statement. Preserve scalar/list and encoded-document handling. Add negative tests for split statements, negated operators, and relevant deny statements; explicitly bound supported policy shapes instead of claiming a full IAM evaluator. Acceptance: the split-statement fixture exits 1; missing tenant identity is treated as an environment problem. AWS statement-condition semantics: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html

## F3 — Medium: Outpost timeout delegates to an absent handler

`cmd_outpost_delete` intentionally exits 0 after an uninstall timeout and promises daily cleanup. `_SWEEP_TYPES` excludes Outpost; `_reap_handler` supplies only a generic direct delete, without uninstall/poll sequencing. Probe F3 confirms the timeout result and missing handler. A setup-created Outpost can therefore remain outside the promised fallback. Implement a resource-specific Outpost cleanup handler and an explicit deferred outcome with a durable retry owner. Do not simply add Outpost to the generic list. Acceptance: timeout followed by a later successful reap, already-uninstalled objects, absent objects, and permanent uninstall failure are covered. Changing the documented timeout exit requires a spec/consumer compatibility decision.

## F4 — Medium: resource searches cannot establish completeness

`_reap_find` takes 50 matches; `_reap_sweep_type` takes 100 without pagination metadata. Probe F4 supplies a full page: one query, no continuation, no blocking result. Similar limits occur in `_find_sa`, `_find_cli_deployment`, `_find_policy`, and connector/sensor/Outpost searches. Missing matches can become false absence; destructive uniqueness checks cover only the returned page. Add pagination where supported, or an explicit incomplete result that prevents destructive conclusions. Acceptance: match or duplicate beyond the first page, repeated cursors, and a server ignoring pagination. Session-report pagination and audit-limit reporting are already fixed; preserve those protections rather than reopening them.

## F5 — Medium: invocation validation is scattered and permissive

`_flag` accepts the following option as a value: probe F5 turns `--session --commit` into session ID `--commit`. Unknown options are generally ignored, and numeric arguments are converted inside handlers. Introduce standard-library subcommand parsing while preserving existing names, defaults, environment fallbacks, and exit 2. Validate before authentication or mutation: missing values, unknown flags, duplicate options, cloud choices, positive scan intervals, bounded timeouts, and meaningful session/lab identifiers. Acceptance: malformed mutating commands exit 2 with zero API/subprocess calls. Also validate `_keypair_dir` inputs such as `.` and `..`; its current character substitution does not establish directory containment.

## F6 — Medium: CSP verification can pass without an account

`_verify_csp` checks GCP command return status but ignores the account list. Probe F6 returns exit 0 with `[]`, and verification succeeds. AWS probes STS; GCP and Azure checks offer different levels of assurance, so the shared `verify` name overstates consistency. Define the minimum promise per provider: credential presence, selected identity, intended account/project/subscription, and a bounded authenticated read where needed. Acceptance: empty GCP account list and wrong target cannot pass; missing, expired, or denied credentials produce exit 3. Verify actual provider commands against their documentation before implementation; the probe establishes local acceptance behavior, not a live credential failure.

## F7 — Policy decision: unknown cleanup coverage is nonblocking

`_reap_one` returns an alert with `blocked=False` when a name or handler is missing. Probe F7 confirms this, and `test_committed_reap_exits_0_when_alerts_are_unactionable` deliberately locks it in. This differs from both the original bug and the fr branch's broader blocking policy. `cmd_reap` success consequently means no known blocking result, not proven absence of every resource. Decide which resource types the runtime guarantees to clean, and represent `removed`, `absent`, `deferred`, `unknown`, and `failed` separately. Acceptance: guaranteed types never disappear into unknown coverage; unsupported types produce an actionable record. Do not restore blanket blocking without reviewing why PR #1 narrowed it.

## F8 — Medium: lease cleanup hides failed revocations

`_revoke` and `_drop_secret` suppress all `SystemExit`, including API authorization and transport failures. `cmd_lease_delete` then removes local files, prints “revoked”, and exits 0. Probe F8 confirms that result when both remote APIs fail. `_iq` already distinguishes expected missing-secret errors, so outer blanket suppression loses useful information. Return structured outcomes, tolerate confirmed absence, report failed revocation truthfully, and preserve enough nonsecret identity to retry. Acceptance: already-absent remains successful; denied or unavailable APIs produce an incomplete result and recovery instructions. Revocation need not disconnect existing nodes; the defect is claiming an unconfirmed remote operation succeeded.

## F9 — High: lease key matching crosses lab boundaries

`_mint_authkey` and `cmd_lease_delete` use a raw description prefix to identify ownership. Probe F9 shows `dev-te-dev-aws-` also matching the key for `te-dev-aws-extra`, causing `_mint_authkey` to revoke both labs' keys. Store or parse an unambiguous owner plus generated suffix, and share that identity rule across ensure/delete. Check `_secret_names` normalization collisions and define concurrent plays of the same lab: keys, local files, and team secrets are currently per-lab. Acceptance: similarly prefixed lab names do not affect one another; multiple owned keys are handled deterministically; overlapping ensure/delete operations are either serialized or explicitly rejected.

## F10 — Medium: policy control resolution silently substitutes

`_resolve_dockerfile_control` prefers the exact root-user control but falls back to the first search result. Probe F10 supplies only another control, which is accepted. `cmd_policy_ensure` can therefore create a fixture that grades a different condition from its documented default. Require an exact, unique default match; make an explicit `--rule-id` override authoritative. If custom search should choose a different control, define that separately and reject ambiguity. Acceptance: no exact default match fails with exit 3; multiple candidates cannot silently choose one; explicit overrides preserve intended behavior. No claim is made that the live tenant currently lacks the correct control.

## D1 — Refactor along responsibilities, preserving deployment simplicity

The runtime has 2,267 lines and 34 command handlers. Size alone is not the problem: HTTP clients, parsing, assertions, cleanup policy, output publication, and operator lease lifecycle change for different reasons. Extract a small importable package behind the same executable: CLI boundary, provider clients, resource operations, pure assertions, cleanup orchestration, and operator lease support. Keep Terraform outside it and preserve stdlib-only runtime dependencies. Do not introduce a provider/plugin framework merely to reduce line count. Acceptance: same command/output/exit contracts, installable image layout, and independently testable helpers; `main` owns process exits rather than deep transport helpers terminating orchestration.

## D2 — Consolidate shared operational policy

`api`, `_gql`, `_kc_call`, `_ts`, `_iq`, and reaper `_instruqt` duplicate transport concerns with different failure semantics. Share timeout budgets, safe retry decisions, secret redaction, and typed transport errors while keeping provider response parsing explicit. A command-scoped Wiz client can reuse authentication instead of `token_and_dc` running for every API call; refresh only on a defined expiry/auth path. Centralize complete enumeration and exact/unique selection rather than repeating `next`, sorting, and partial-page assumptions. `_cli` needs bounded subprocess execution. Acceptance: failure classification, retry counts, and token reuse are tested through transport boundaries, including GraphQL partial-data responses, instead of only mocking those boundaries away.

## D3 — Define successful ensure and inspect precisely

`_ensure_sa` succeeds without credentials when a sensor account exists; `cmd_serviceaccount_ensure` instead deletes and recreates a CLI deployment. `cmd_policy_ensure` and `cmd_outpost_ensure` accept existing names without reconciling configuration. D3 probes confirm empty sensor output and ignored policy threshold changes. These may be intentional contracts, but “idempotent converge” alone does not explain them. Specify postconditions per resource, ownership, secret recovery/rotation, and interrupted-run behavior. For shared policies, report drift before mutating other labs' fixture. Also define whether `lease inspect --require reachable` promises node freshness or usable SSH: it currently accepts freshness even without a local private key.

## D4 — Test behavior across boundaries

The current suite reaches 25 of 34 `cmd_*` bodies when traced with `sys.settrace`; this is handler reachability, not line/branch coverage. Unreached: `cmd_wiz_queries`, `cmd_audit_user`, `cmd_connector_delete`, `cmd_instance_inspect`, `cmd_sensor_ensure`, `cmd_sensor_delete`, `cmd_user_ensure`, `cmd_user_delete`, `cmd_user_login_url`. Prioritize destructive and credential paths, not an arbitrary coverage percentage. Convert accepted observations into tests for the corrected behavior; include partial remote success, duplicate identities, pagination boundaries, and repeated teardown. Preserve real temporary-file/key-generation checks. Green mocked tests do not justify skipping live validation when changing an API payload, provider semantics, or resource lifecycle; revisit that blanket claim in the spec.

## D5 — Make releases validate the artifact they publish

[Build](../.github/workflows/build.yml) publishes tags without depending on [lint/tests](../.github/workflows/lint.yml) or an image smoke test. [Dockerfile](../Dockerfile) floats its base and several downloaded CLIs, including wizcli; a source tag alone does not make rebuilds reproducible. Gate publication on checks for the same commit, test Python 3.12, smoke-test installed binaries and entrypoint, record dependency versions, and use verified artifacts/digests where practical. [Reaper workflow](../.github/workflows/reap.yml) defaults manual commit to true despite its dry-run comment; the repository variable can also override an unchecked input. Make mode precedence explicit and test it; update the pinned image when accepted runtime fixes are released.

## Review decisions and implementation order

| Order | Reviewer action and completion criterion |
|---|---|
| 1 | Reproduce F1–F10 at the target SHA; label each accepted, rejected with rationale, or requiring live evidence. Read PR #1/fr differences before proposing cleanup changes. |
| 2 | Correct mutation retries, statement-level IAM assertions, and lease ownership; add desired-behavior regressions. |
| 3 | Decide cleanup coverage/deferred outcomes and ensure postconditions; then implement lifecycle, pagination, parsing, and error-classification fixes. |
| 4 | Extract shared boundaries after contracts stabilize; preserve CLI compatibility and keep cloud-specific behavior explicit. |
| 5 | Gate and verify the release, update consumer image pins, and validate changed external payloads on a controlled lease. |
