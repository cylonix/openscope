# OpenScope Website Generation Pack

This folder contains self-contained Markdown briefs for generating the `open-scope.org` website with Google Stitch or a similar code-generation tool.

These files are intentionally written so the generator does not need to fetch unpublished repository documents. Each page brief includes:

- the page goal
- required sections
- required copy
- visual direction
- CTA behavior
- Mermaid diagrams embedded directly in the file where needed

## Generation Order

1. [`homepage.md`](./homepage.md)
2. [`why_openscope.md`](./why_openscope.md)
3. [`how_it_works.md`](./how_it_works.md)
4. [`use_cases.md`](./use_cases.md)
5. [`compare.md`](./compare.md)
6. [`docs_page.md`](./docs_page.md)

## Global Rules

- Use a dark, security-forward visual style.
- Do not generate a generic SaaS template.
- Use semantic HTML and accessible color contrast.
- Prefer rendering Mermaid directly when supported.
- If Mermaid is not supported, generate polished visuals that preserve the same structure and meaning.
- Use the exact GitHub URLs below:
  - Repo: `https://github.com/cylonix/openscope`
  - Releases: `https://github.com/cylonix/openscope/releases`
- Keep the primary CTA as `Download OpenScope`.
- Keep the secondary CTA as `View Code`.

## Global Navigation

Top-level navigation:

- `Why OpenScope`
- `How It Works`
- `Use Cases`
- `Compare`
- `Docs`
- `GitHub`

Suggested routes:

- `/`
- `/why-openscope`
- `/how-it-works`
- `/use-cases`
- `/docs`

`GitHub` points to the repository. `Download` points to the releases page.

## Shared Visual Direction

### Palette

- `--bg`: `#07111A`
- `--bg-elevated`: `#0D1B27`
- `--panel`: `#102332`
- `--text`: `#EAF4FB`
- `--muted`: `#9FB4C3`
- `--line`: `#214052`
- `--teal`: `#5EE7D8`
- `--cyan`: `#33C7FF`
- `--blue`: `#4D7CFE`
- `--green`: `#7EE081`
- `--warning`: `#FFB86B`

### Typography

- Headings: `Fraunces`, `DM Serif Display`, or similar
- Body/UI: `Manrope`, `Plus Jakarta Sans`, or `IBM Plex Sans`
- Mono: `IBM Plex Mono` or `JetBrains Mono`

### Motion

- restrained reveals
- subtle sticky header transition
- meaningful hover states
- no excessive animation

## Shared Brand Message

OpenScope is an AI agent capability broker that turns raw privileged access into scoped, auditable, policy-bound actions.

Core ideas to repeat consistently:

- Contain keys
- Remove raw powers
- Expose only approved actions
- Keep raw privileged interfaces out of the agent path
- Apply policy at the action and parameter level
