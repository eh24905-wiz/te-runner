# CLAUDE.md

## Documentation rules — every doc, README, comment, commit message, PR body

1. State each fact once, in the one place a reader would look for it. Never
   summary-then-detail; never restate the request or narrate a diff.
2. Hard budgets: new doc ≤ 100 lines; section ≤ 120 words; commit body ≤ 5
   lines; code example ≤ 10 lines; headings h3 max. Over budget → cut
   content that doesn't change the reader's next action, not wording.
   `tracks/*/research.md` is budgeted by tier in
   `.claude/agents/doc-researcher.md`.
3. Two things carry weight: a **reproducer** (exact command + expected exit
   code) for live external state, and a **bare page URL** for external
   platform semantics no code of ours enforces. For our own code, name the
   symbol — never a path with line numbers. Nothing else needs a citation;
   git holds the rest. Prefer a constraint the code fails without over one
   written down.
4. Banned: "comprehensive", "robust", "leverage", "it's important to note",
   "needs to be considered", "best practices", intro/outro paragraphs.
5. Tables for enumerable facts; prose only for causality and decisions.
6. Code comments state a non-obvious constraint (WHY) and nothing else, never
   what the code does. Zero-narration applies — see below.
7. Docs end with next actions or open questions, not a recap.

## Durable technical knowledge — zero narration

Governs every mechanism record: `measurements.yaml`, `tracks/*/research.md`,
track-spec technical notes, code comments.

8. Timeless present tense. Exact enum names, API parameter paths and role
   names, not prose summaries.
9. Cover three axes, in the host file's own format — YAML keys, a table, a
   comment. Never imported markdown scaffolding:

   | Axis | Content |
   |---|---|
   | Prerequisites | flags, API params, IAM roles required to work |
   | Failure states | observable enums and emitted alerts when absent |
   | Convergence | transition durations, latencies, timeouts |

10. Never: dates, lease/sandbox ids, session records, commits, `file:line`,
    doc-hierarchy arguments, what broke, what anyone assumed, how we found
    out, "the earlier row was wrong". Keep the number and its reproducer.
11. Correct a wrong record by replacing it, never by annotating it. A
    mechanism claim carrying no reproducer does not outrank published docs.
12. Decisions are not mechanisms: a plan-gate choice keeps its owner and
    date, names the constraint that forced it, and does not restate the
    mechanism.

## Durable knowledge → git, not auto-memory

Do not use auto-memory (`.claude/**/memory/`) — it dies on a fresh clone. Any
fact worth keeping goes in a git-tracked file: repo docs, a README, or a code
comment stating WHY.

Copy this file into each new lab repo (te-platform-probe, pilots) at
creation.
