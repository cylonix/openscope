# OpenScope demo — synthetic test corpus

Two sample repos a prospect can use to exercise OpenScope **without uploading
their own confidential IP**:

- [`northwind-rtl/`](./northwind-rtl) — RESTRICTED. Stands in for chip
  crown-jewels (RTL, SPICE, SDC, licensed IP, spec, PDK notes, secrets). Every
  file should be **DENIED** at the perimeter.
- [`northwind-webapp/`](./northwind-webapp) — ALLOWED. Ordinary app code with
  no IP, markers, or secrets. Every file should be **ALLOWED** through (and
  still audited + receipted).

The point is the contrast: a leak-detector you trust is one that blocks the
*right* things and lets ordinary work flow. A scanner that blocks a plain
README is theater.

See [`EXPECTED.md`](./EXPECTED.md) for the answer key — run the corpus and
confirm OpenScope's verdicts match.

Everything is 100% synthetic. "Northwind Semiconductor" is fictional; the AWS
key is AWS's own documented example (non-functional); the private-key and
encrypted-IP blobs are fake. Safe to share publicly.

## Use it

- **In the demo UI:** the two-column governed console has one-click sample
  chips drawn from these files.
- **By hand / your own agent:** point Cursor, Codex CLI, or Claude Code at the
  OpenScope endpoint (see `docs/bring-your-own-agent.md`) and ask it to work in
  each repo. Watch `northwind-rtl` get blocked and `northwind-webapp` flow.
