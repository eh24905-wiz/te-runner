# Review: findings ranked by return on effort

Every finding from the code-level and design-level reviews, one row each, ranked by payoff per unit
of work. Effort: S = under a day, M = days, L = a week or cross-repo. Baseline: `ruff` clean, radon
average A with 13 functions at C, 232 tests in `test_wizlab.py` green (plus 5 reaper, 1 entrypoint).
Symbols name the `wizlab` package unless a path is given. The last column is the blast radius: what the fix
touches, what depends on it (tests, labs, other repos), and where the fixing agent looks next.

## Tier 2 — structural, each retires several rows below it

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 15 | Hand-rolled `_flag`: `--require` validated nine times, `int(_flag(...) or "N")` ten times | argparse per verb with `FLAGS` as its spec: `choices=` for `--require`, `type=int` | S | 86 `_flag` sites plus six `"--x" in args` switches; every `cmd_*` takes `args` as a list. `FlagParsing` tests call `_flag` directly. Unknown flags already exit 2 through `_check_flags`, so this is shape, not contract. |

## Tier 3 — cross-repo or operator-facing

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 22 | `lease` (~320 lines), `wiz queries`, `wiz type`, `audit user` run only on an operator machine, yet each fix is an image tag and a repin in 13 repos; `te-labkit-v2/scripts/dev-access.py` (108 lines) holds the other half of dev access | move them to labkit; image keeps only the entrypoint's `TS_AUTHKEY` path | M | Moves `_ts`, `_iq`, `_scrub`, `_keypair_dir`, `_owned_keys` and the `LeaseDevAccess` tests with them; `_post` and `_submissions` are shared, so the moved code imports or copies them. Labkit docs naming `wizlab lease`: `CLAUDE.md`, `authoring/pipeline.md`, track `research.md` files. The `SPEC.md` lease section moves too. |

## Tier 4 — measure before deciding

| # | Finding | Do | Effort | Blast radius → guidance |
|---|---|---|---|---|
| 30 | The reaper's audit layer, its five-outcome model and `UNKNOWN` handling exist for free-named GUI creates. Every lab now instructs `lab-<sid>-*` names; nothing measures how often audit removes what the sweep missed | read the `audit-only` count `cmd_reap` prints on its summary line across several weeks of `reap.yml` logs; near zero → keep audit as report, sweep is the delete path | L | `_reap_enumerate`, `_reap_one`, `_input_name`, `_REAP_OVERRIDES`. `SPEC.md` records the current exit-0 promise as an operator decision, so a change there goes through the change process. |

## Holds up — keep

Exit codes 0/1/2/3 (platform-forced). The `lab-<sid>` stem (replaced an account stem after a live
collision). `_submissions` owning the resend budget by document type. Grading enums, never UI labels.
Every measurement carrying its reproducer. One pinned image per lab.

## Next actions

1. #15's argparse shape, in `wizlab/cli.py` and `core.py`.
2. #22 needs a labkit PR and a repin round; batch it with the next verb release.
