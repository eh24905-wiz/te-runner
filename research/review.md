# Review: findings ranked by return on effort

Every finding from the code-level and design-level reviews, one row each, ranked by payoff per unit
of work. Effort: S = under a day, M = days, L = a week or cross-repo. Baseline: `ruff` clean, radon
average B with 13 functions at C, 233 tests in `test_wizlab.py` green (plus 5 reaper, 1 entrypoint).
Symbols name `wizlab/wizlab` unless a path is given. The last column is the blast radius: what the fix
touches, what depends on it (tests, labs, other repos), and where the fixing agent looks next.

## Tier 1 — small, immediate, no contract change

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 4 | `token_and_dc` runs per `api()` call: `find_connector` mints up to three tokens, `cmd_session_verify` mints twice back to back, `_wiz_login_url` mints one only for `tid`; part of the measured 2–6s per check | module-level token cache keyed on tenant, refresh on 401 | S | Six call sites. `api` re-mints on every retry iteration; `cmd_reap` already threads `tok, dc` into `_gql`, which is the shape to keep. Tests patch `token_and_dc` nine times and `_post` three; `TransientGraphqlErrors` and `MutationSubmissionBudget` count `_post` calls, so the cache must be resettable (module dict cleared in `setUp`). A 401 retry re-sends the document: allow it only where `_submissions` allows a resend. |
| 11 | `te-labkit-v2/tracks/wiz-workflows-201/track-spec.json` promises `wizlab workflow delete`; `SPEC.md` rules it out | fix the track-spec | S | The `cleanup` field of that spec. Replacement: `wizlab user reap`, since `AutomationWorkflow` is in `_SWEEP_TYPES`. Labkit PR, no runner change. |
| 13 | `_aws`/`_gcp`/`_az` are split by `_wiz_gcp_sa` | group the CLI shims | S | Pure move; nothing resolves at import. #15 removes `_flag`, so do this inside #16's split rather than as its own reorder diff. |

## Tier 2 — structural, each retires several rows below it

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 14 | `die()` is control flow: 113 sites (67 exit 3, 42 exit 2, 1 exit 1), a non-fatal twin `_gql` for the reaper, `contextlib.suppress(SystemExit)` in `_revoke`/`_drop_secret`, `except SystemExit` rollback in `cmd_lease_ensure`. `cmd_lease_delete` exits 0 and prints "revoked" when both remote APIs fail | raise `WizlabError(code, msg)`; convert once in `main`; `_gql` becomes `api` with errors returned; lease delete reports what actually failed | M | 54 `assertRaises(SystemExit)` plus every `_exit` helper call handlers directly, not through `main`, so keep `die` as a shim that raises `WizlabError` and let the test helpers catch either until #20 lands. `_iq(tolerate=)` is the model for expected absence: `_drop_secret` keeps it, `_revoke` needs a 404 tolerance, and anything else is a failed step that `cmd_lease_delete` names and exits 3 on. Reaper `_instruqt` has no `HTTPError` catch and tracebacks to exit 1; same defect, other transport. |
| 15 | Hand-rolled `_flag`: fixed twice in the log, unknown flags silently ignored (`SPEC.md` records it), `--require` validated nine times, `int(_flag(...) or "N")` ten times | argparse subparsers: `choices=` for `--require`, `type=int`, unknown flag exits 2 | M | 84 `_flag` sites plus six `"--x" in args` switches (`--all`, `--commit`, `--dry-run`, `--exact-name`, `--match-only`, `--no-self`); every `cmd_*` takes `args` as a list. `FlagParsing` tests call `_flag` directly. Cross-repo: unknown-flag exit 2 turns a misspelled flag in any of the 47 lab wrappers from a silent pass into a learner failure, so grep every wrapper's flags against the parser before the tag ships. `--min-runner` must parse before any other validation. After #14. |
| 16 | One 2,783-line file with no `.py`: SourceFileLoader hacks in three files, explicit ruff paths, no editor tooling. Stdlib-only still holds and stays | package `wizlab/` with `__main__.py`, two-line shim at `/usr/local/bin/wizlab`; no runtime deps added | M | Dockerfile `COPY`, `lint.yml` ruff/xenon/radon paths, both test loaders (#10). The executable path stays: reaper `_wizlab` and every lab call `wizlab` by name. Do after #14 and #15 so module boundaries follow the new error and CLI layers. |
| 17 | Repetition: `.get("nodes") or []` ×18; exact-name `next(...)` ×5; `EXEC_OUTPUT` append ×4; `_norm_account(_flag(...) or die(...))` ×4; `_flag("--name") or _lab_stem(_session_id())` ×5; `_kc_call` status-then-die ×6; status-first sort ×2; `WIZ_<TENANT>_X or WIZ_X` ×2 | `_nodes`, `_exact`, `_emit`, `_account_id`, `_named(args, suffix)`, `_kc_call(ok=)`, `_prefer`, `_tenant_env` | M | Pure refactor; tests route on query text and exit codes, not on these expressions. Re-run `radon`: the 14 C-rated functions include `find_connector`, `_verify_csp`, `_inspect_aws_trust`, `_reap_enumerate`, and these helpers are what lowers them. |
| 20 | Tests mock `api` per handler: seven `_exit` and seven `_api` routers dispatch on query substrings (32 sites) and re-implement the server; payload shapes are never checked | one module-level `exit_code(fn, argv, **patches)`; one fake at `_post` fed by recorded captures | M | Eight handlers have no test: `cmd_connector_delete`, `cmd_instance_inspect`, `cmd_sensor_ensure`, `cmd_sensor_delete`, `cmd_user_ensure`, `cmd_user_delete`, `cmd_user_login_url`, `cmd_wiz_queries`. Cover the destructive and credential handlers first. Coordinate with #14 (error type) and #29 (return vs exit). `Pagination._pages` is the shape of a fake fed by variables rather than query text. |

## Tier 3 — cross-repo or operator-facing

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 21 | 47 copies of `case $? in 0) exit 0 ;; *) exit 1 ;; esac` across 13 lab repos (44 that form, 2 `0) ;;`, 3 commented out) | `wizlab --check <noun> <verb>` collapses to 0/1 and prints the real code on stderr | S + repins | `main` gains one leading switch. `te-labkit-v2/authoring/architecture.md` documents the wrapper and changes with it. Order: ship the tag, repin, then drop wrappers per repo; a wrapper left in place stays correct. |
| 22 | `lease` (~320 lines), `wiz queries`, `wiz type`, `audit user` run only on an operator machine, yet each fix is an image tag and a repin in 13 repos; `te-labkit-v2/scripts/dev-access.py` (108 lines) holds the other half of dev access | move them to labkit; image keeps only the entrypoint's `TS_AUTHKEY` path | M | Moves `_ts`, `_iq`, `_scrub`, `_keypair_dir`, `_owned_keys` and the `LeaseDevAccess` tests with them; `_post` and `_submissions` are shared, so the moved code imports or copies them. Labkit docs naming `wizlab lease`: `CLAUDE.md`, `authoring/pipeline.md`, track `research.md` files. The `SPEC.md` lease section moves too. |
| 23 | `--min-runner` has never fired: pins v0.1.43 (9 repos), v0.1.44 (1), v0.1.45 (3); floors v0.1.27–44, every floor at or below its pin (gcp-connector-101 is equal). Three dev repos carry no floor. The floor is hand-written, so it cannot catch a lab calling a verb newer than its pin | labkit CI check: pin ≥ floor, and verbs used ≤ verbs in the pinned tag | M | Inputs per lab repo: the `te-runner:vX` pin in `sandbox.hcl`, the `--min-runner` in its check, the `wizlab <noun> <verb>` calls. Verb list at a tag: `git show vX:wizlab/wizlab` and read `VERBS`. Nothing in the runner changes. |
| 24 | Tenant keying is half-built: `WIZ_<TENANT>_*`, `_TENANT_SSO`, reaper `TENANTS`, and "TBCMP" baked as default in four places (`token_and_dc`, `_wiz_azure_object_id`, `_wiz_login_url`, reaper `REAP_SESSIONS_TENANT`); one live tenant | one tenant config dict with no baked default, or drop the indirection until tenant two exists | S | `reap.yml` wires `WIZ_TBCMP_*` secrets and no `WIZ_TENANT`, so removing the default needs `WIZ_TENANT` set there and in every lab env, or the fallback to `WIZ_CLIENT_ID` keeps working. `_tenant_env` from #17 is the seam. |
| 26 | `ensure` postconditions differ per noun with no stated rule: `_ensure_sa` exits 0 with no credentials on an existing account; `cmd_serviceaccount_ensure` deletes and re-mints; `cmd_policy_ensure` ignores `--count-threshold` on an existing policy; `cmd_outpost_ensure` does not reconcile; `cmd_lease_inspect` passes with no local private key | write the per-noun postcondition in `SPEC.md`, then make each verb meet it | M | `cmd_connector_ensure` is the one verb that reconciles; use its shape. Tests pin today's behaviour: `ServiceAccountGrading` and `PolicyGrading` assert exit 0 with no mutation on `existing=True`. Lab impact: a solve re-run through `_ensure_sa` emits no `WIZ_API_CLIENT_SECRET`, so the sensor install line downstream gets an empty value. Change `SPEC.md` first (operator approves), then code and tests together. |
| 29 | `_KcSession` is a namedtuple every caller unpacks positionally with `_`; 24 of 38 handlers end in `sys.exit(0)` | attribute access or a plain tuple; let `main` exit 0 on return | S | Three `_kc_session` callers. The 54 `assertRaises(SystemExit)` include success paths, so handler returns break tests until #20's `exit_code` helper treats a plain return as 0. The 14 handlers that already return or branch-exit show it works. |

## Tier 4 — measure before deciding

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 30 | The reaper's audit layer, its five-outcome model and `UNKNOWN` handling exist for free-named GUI creates. Every lab now instructs `lab-<sid>-*` names; nothing measures how often audit removes what the sweep missed | read the `audit-only` count `cmd_reap` prints on its summary line across several weeks of `reap.yml` logs; near zero → keep audit as report, sweep is the delete path | L | `_reap_enumerate`, `_reap_one`, `_input_name`, `_REAP_OVERRIDES`. `SPEC.md` records the current exit-0 promise as an operator decision, so a change there goes through the change process. |

## Holds up — keep

Exit codes 0/1/2/3 (platform-forced). The `lab-<sid>` stem (replaced an account stem after a live
collision). `_submissions` owning the resend budget by document type. Grading enums, never UI labels.
Every measurement carrying its reproducer. One pinned image per lab.

## Next actions

1. #14 then #15 then #16, in that order; each makes the next smaller. Two constraints: tests call handlers
   directly and catch `SystemExit` 54 times, so #14 and #29 break the suite unless #20's `exit_code` helper
   lands with them; and #15's unknown-flag exit 2 turns a misspelled flag in any of the 47 lab wrappers into
   a learner failure, so grep every wrapper's flags against the parser before that tag ships.
2. #21 and #22 need a labkit PR and a repin round; batch them with the next verb release.
