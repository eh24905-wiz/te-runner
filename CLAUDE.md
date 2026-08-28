# CLAUDE.md

## Documentation rules — every doc, README, comment, commit message, PR body

1. State each fact once, in the one place a reader would look for it. Never
   summary-then-detail; never restate the request or narrate a diff.
2. Hard budgets: new doc ≤ 100 lines; section ≤ 120 words; commit body ≤ 5
   lines; code example ≤ 10 lines; headings h3 max. Over budget → cut
   content that doesn't change the reader's next action, not wording.
3. Every claim carries its evidence: `path:line`, an exact command, or a
   measured number. A sentence with none of these is a candidate for
   deletion.
4. Banned: "comprehensive", "robust", "leverage", "it's important to note",
   "needs to be considered", "best practices", intro/outro paragraphs.
5. Tables for enumerable facts; prose only for causality and decisions.
6. Code comments state a non-obvious constraint (WHY) — never what the code
   does or where it came from (carried from v1's GEMINI.md).
7. Docs end with next actions or open questions, not a recap.

Copy this file into each new lab repo (te-platform-probe, pilots) at
creation.
