# CLAUDE.md

## Documentation rules — every doc, README, comment, commit message, PR body

1. State each fact once, in the one place a reader would look for it. Never
   summary-then-detail; never restate the request or narrate a diff.
2. Hard budgets: new doc ≤ 100 lines; section ≤ 120 words; commit body ≤ 5
   lines; code example ≤ 10 lines; headings h3 max. Over budget → cut
   content that doesn't change the reader's next action, not wording.
3. Two things carry weight: a **reproducer** (exact command + expected exit
   code) for live external state, and a **bare page URL** for external
   platform semantics no code of ours enforces. For our own code, name the
   symbol — never a path with line numbers. Nothing else needs a citation;
   git holds the rest. Prefer a constraint the code fails without over one
   written down.
4. Banned: "comprehensive", "robust", "leverage", "it's important to note",
   "needs to be considered", "best practices", intro/outro paragraphs.
5. Tables for enumerable facts; prose only for causality and decisions.
6. Code comments state a non-obvious constraint (WHY) and nothing else. NEVER
   what the code does, and NEVER provenance or narration — no dates, no
   `file:line`, no "measured/proven/ported from", no how we found out.
7. Docs end with next actions or open questions, not a recap.

## Durable knowledge → git, not auto-memory

Do not use auto-memory (`.claude/**/memory/`) — it dies on a fresh clone. Any
fact worth keeping goes in a git-tracked file: repo docs, a README, or a code
comment stating WHY.

Copy this file into each new lab repo (te-platform-probe, pilots) at
creation.
