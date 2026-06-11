# northwind-webapp — ALLOWED

> Synthetic sample repo for the OpenScope demo.

This repo stands in for ordinary, non-sensitive application code — the kind of
work where using a coding agent is **fine**. Nothing here is proprietary IP,
nothing is classification-marked, and there are no secrets. When an agent is
pointed at OpenScope, work in this repo **flows normally** to the model — and
is still audited, still covered by a signed receipt, and still unreadable by
OpenScope operators.

This is the other half of the demo: the point isn't to block everything, it's
to block the *right* things. A scanner that blocks a plain README is theater.

| Path | What it is | Verdict |
|---|---|---|
| `src/cart.ts` | Shopping-cart helper | ALLOW |
| `src/hello.py` | Trivial script | ALLOW |
| `docs/notes.txt` | Meeting notes | ALLOW |

See [`../EXPECTED.md`](../EXPECTED.md) for the full answer key.

## Develop

```bash
npm install
npm run dev
```

MIT licensed.
