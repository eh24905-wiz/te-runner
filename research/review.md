# Review: findings ranked by return on effort

Every finding from the code-level and design-level reviews, one row each, ranked by payoff per unit
of work. Effort: S = under a day, M = days, L = a week or cross-repo. Baseline: `ruff` clean, radon
average B with 13 functions at C, 243 tests in `test_wizlab.py` green (plus 5 reaper, 1 entrypoint).
Symbols name `wizlab/wizlab` unless a path is given. The last column is the blast radius: what the fix
touches, what depends on it (tests, labs, other repos), and where the fixing agent looks next.

## Tier 1 — small, immediate, no contract change

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 11 | `te-labkit-v2/tracks/wiz-workflows-201/track-spec.json` promises `wizlab workflow delete`; `SPEC.md` rules it out | fix the track-spec | S | The `cleanup` field of that spec. Replacement: `wizlab user reap`, since `AutomationWorkflow` is in `_SWEEP_TYPES`. Labkit PR, no runner change. |
| 13 | `_aws`/`_gcp`/`_az` are split by `_wiz_gcp_sa` | group the CLI shims | S | Pure move; nothing resolves at import. #15 removes `_flag`, so do this inside #16's split rather than as its own reorder diff. |

## Tier 2 — structural, each retires several rows below it

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 15 | Hand-rolled `_flag`: fixed twice in the log, unknown flags silently ignored (`SPEC.md` records it), `--require` validated nine times, `int(_flag(...) or "N")` ten times | argparse subparsers: `choices=` for `--require`, `type=int`, unknown flag exits 2 | M | 84 `_flag` sites plus six `"--x" in args` switches (`--all`, `--commit`, `--dry-run`, `--exact-name`, `--match-only`, `--no-self`); every `cmd_*` takes `args` as a list. `FlagParsing` tests call `_flag` directly. Cross-repo: unknown-flag exit 2 turns a misspelled flag in any of the 47 lab wrappers from a silent pass into a learner failure, so grep every wrapper's flags against the parser before the tag ships. `--min-runner` must parse before any other validation. |
| 16 | One 2,783-line file with no `.py`: SourceFileLoader hacks in three files, explicit ruff paths, no editor tooling. Stdlib-only still holds and stays | package `wizlab/` with `__main__.py`, two-line shim at `/usr/local/bin/wizlab`; no runtime deps added | M | Dockerfile `COPY`, `lint.yml` ruff/xenon/radon paths, both test loaders (#10). The executable path stays: reaper `_wizlab` and every lab call `wizlab` by name. Do after #15 so module boundaries follow the CLI layer. |
| 20 | Seven handlers have no test: `cmd_connector_delete`, `cmd_instance_inspect`, `cmd_sensor_ensure`, `cmd_sensor_delete`, `cmd_user_delete`, `cmd_user_login_url`, `cmd_wiz_queries`; five `_api` routers still dispatch on query substrings | cover the destructive and credential handlers first, through `exit_code(fn, argv, wiz=FakeWiz(...))`; move the remaining routers onto `FakeWiz` as their classes are touched | M | `ServiceAccountGrading` and `PolicyGrading` are the reference shape: the fake answers by top-level field and records `calls`/`docs`. |

## Tier 3 — cross-repo or operator-facing

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 21 | 47 copies of `case $? in 0) exit 0 ;; *) exit 1 ;; esac` across 13 lab repos (44 that form, 2 `0) ;;`, 3 commented out) | `wizlab --check <noun> <verb>` collapses to 0/1 and prints the real code on stderr | S + repins | `main` gains one leading switch. `te-labkit-v2/authoring/architecture.md` documents the wrapper and changes with it. Order: ship the tag, repin, then drop wrappers per repo; a wrapper left in place stays correct. |
| 22 | `lease` (~320 lines), `wiz queries`, `wiz type`, `audit user` run only on an operator machine, yet each fix is an image tag and a repin in 13 repos; `te-labkit-v2/scripts/dev-access.py` (108 lines) holds the other half of dev access | move them to labkit; image keeps only the entrypoint's `TS_AUTHKEY` path | M | Moves `_ts`, `_iq`, `_scrub`, `_keypair_dir`, `_owned_keys` and the `LeaseDevAccess` tests with them; `_post` and `_submissions` are shared, so the moved code imports or copies them. Labkit docs naming `wizlab lease`: `CLAUDE.md`, `authoring/pipeline.md`, track `research.md` files. The `SPEC.md` lease section moves too. |
| 23 | `--min-runner` has never fired: pins v0.1.43 (9 repos), v0.1.44 (1), v0.1.45 (3); floors v0.1.27–44, every floor at or below its pin (gcp-connector-101 is equal). Three dev repos carry no floor. The floor is hand-written, so it cannot catch a lab calling a verb newer than its pin | labkit CI check: pin ≥ floor, and verbs used ≤ verbs in the pinned tag | M | Inputs per lab repo: the `te-runner:vX` pin in `sandbox.hcl`, the `--min-runner` in its check, the `wizlab <noun> <verb>` calls. Verb list at a tag: `git show vX:wizlab/wizlab` and read `VERBS`. Nothing in the runner changes. |
| 26 | `ensure` postconditions differ per noun with no stated rule: `_ensure_sa` exits 0 with no credentials on an existing account; `cmd_serviceaccount_ensure` deletes and re-mints; `cmd_policy_ensure` ignores `--count-threshold` on an existing policy; `cmd_outpost_ensure` does not reconcile; `cmd_lease_inspect` passes with no local private key | write the per-noun postcondition in `SPEC.md`, then make each verb meet it | M | `cmd_connector_ensure` is the one verb that reconciles; use its shape. Tests pin today's behaviour: `ServiceAccountGrading` and `PolicyGrading` assert exit 0 with no mutation on `existing=True`. Lab impact: a solve re-run through `_ensure_sa` emits no `WIZ_API_CLIENT_SECRET`, so the sensor install line downstream gets an empty value. Change `SPEC.md` first (operator approves), then code and tests together. |

## Tier 4 — measure before deciding

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 30 | The reaper's audit layer, its five-outcome model and `UNKNOWN` handling exist for free-named GUI creates. Every lab now instructs `lab-<sid>-*` names; nothing measures how often audit removes what the sweep missed | read the `audit-only` count `cmd_reap` prints on its summary line across several weeks of `reap.yml` logs; near zero → keep audit as report, sweep is the delete path | L | `_reap_enumerate`, `_reap_one`, `_input_name`, `_REAP_OVERRIDES`. `SPEC.md` records the current exit-0 promise as an operator decision, so a change there goes through the change process. |

## Holds up — keep

Exit codes 0/1/2/3 (platform-forced). The `lab-<sid>` stem (replaced an account stem after a live
collision). `_submissions` owning the resend budget by document type. Grading enums, never UI labels.
Every measurement carrying its reproducer. One pinned image per lab.

## Next actions

1. #15 then #16, in that order; each makes the next smaller. One constraint: #15's unknown-flag exit 2
   turns a misspelled flag in any of the 47 lab wrappers into a learner failure, so #23's labkit check
   runs against every wrapper before that tag ships.
2. #21 and #22 need a labkit PR and a repin round; batch them with the next verb release.
