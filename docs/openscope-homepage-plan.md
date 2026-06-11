# OpenScope Homepage Revision Plan

## Context for Claude Code

This is a plan for revising the openscopeai.com homepage. The goal is to evolve the current messaging — which positions OpenScope as a "capability broker for AI agents" targeting the open-source developer community — so that enterprise prospects evaluating a *complete* agentic-workflow risk solution can immediately recognize it as the answer to their problem, while keeping the existing developer-facing surface intact.

**Stage of the company:** Pre-first-customer. Goal of the website is to convert qualified enterprise prospects into design-partner conversations, while continuing to serve the existing OSS/developer community as a top-of-funnel adoption path.

**Do not over-emphasize:** the team's other product (Cylonix SASE) or its history. A footer mention is fine; do not put it in the hero, value prop, or any section above the fold.

**Do not lead with:** AI router or DLP features as the headline. These are part of the complete solution but are not the unique value. The action broker is the wedge.

## Strategic framing (the messaging spine)

Everything below flows from this core idea — Claude Code should internalize this before writing copy:

> **The agent trust perimeter has two halves:**
> - **What the agent sees** (inputs to the model): prompt security, PII/IP scrubbing, model routing
> - **What the agent does** (outputs from the agent): capability brokering, scoped actions, circuit breaker
>
> Most tools address one half. OpenScope is built for both — because in a real production workflow, you cannot govern one without the other. **The action broker is where most platforms stop, and where OpenScope is built to be uniquely strong.**

This framing must be visible (verbally or architecturally) within the first screen of the homepage.

## Audience priority

In order:

1. **Primary:** A platform/security lead at an enterprise running AI agents in production (financial services, healthcare, regulated SaaS, critical infrastructure). They are evaluating how to govern agent risk and are aware of both the prompt-side data leak problem and the action-side blast-radius problem.
2. **Primary:** A CISO or Head of Risk forwarded the site by the platform lead above. They need to read the page and conclude "this is a serious vendor I should let my team evaluate."
3. **Secondary, do not break:** The existing OSS/developer audience who is installing OpenScope locally for use with Claude Code, Codex, OpenClaw, etc. The current site serves them well; we do not want to alienate them with enterprise-speak.

The hero and first-screen messaging should serve (1) and (2). Deeper sections, install instructions, and CLI examples continue to serve (3).

## Concrete copy: hero + first screen

### Hero

**Eyebrow / category line:**
`AI Agent Trust Perimeter`

**Headline:**
`Don't trust your agents with raw power. Give them a perimeter.`

**Subhead:**
`OpenScope governs both what your AI agents see and what they do — prompt security on the way in, scoped capabilities and a circuit breaker on the way out. Customer-deployed, open source, one trust boundary instead of two.`

**Primary CTA:** `Talk to us about a design partnership`
**Secondary CTA:** `View on GitHub`

(The existing "Download OpenScope" CTA stays prominent further down the page, in the developer-facing section.)

### Immediately below hero: the architecture statement

A short section, two-column or with the architecture diagram on one side and the framing text on the other. The text reads roughly:

> **The trust perimeter has two halves.**
>
> *What the agent sees.* Prompt security removes PII, credentials, and proprietary IP before any request reaches an external model. Route across Claude, GPT, Gemini, or self-hosted models through your own infrastructure.
>
> *What the agent does.* Capability brokering replaces raw privileged access — shell, database credentials, publishing pipelines — with scoped, auditable actions. A circuit breaker provides an out-of-band kill switch when something goes wrong.
>
> **Most platforms address one half. We're built for both.**

The architecture diagram should be the Secure AI Router + Executor diagram you already have, but evolved per the notes below.

## Architecture diagram — evolution notes

Take the existing `openscope-ai-router-dark-with-executor` diagram and update it for the homepage. Goals:

1. **Visually weight the action broker / executor side.** Right now the router and executor read as roughly co-equal. The executor should be larger, more prominent, or centered such that a visitor's eye lands on it as the "main thing." The router/DLP side is the *entry path*, not a peer product.

2. **Clear data flow direction.** Arrows should make it obvious: prompts flow in → through DLP/router → to model → response comes back → agent decides → action gets brokered → executed (or denied). A visitor should be able to trace the flow without reading labels.

3. **Customer-owned boundary explicit.** Draw a clear dotted box labeled "your VPC" or "customer-deployed" around everything except the model providers and external systems. Communicates the deployment story without words.

4. **Circuit breaker visible.** Add a small but clearly-labeled element for the out-of-band kill switch / human approval path. Even if it's a small icon and label on the executor side, it must be present. Mission-critical buyers will spot it; everyone else can ignore it.

5. **Human-in-the-loop path visible** where it exists. Same logic — costs nothing visually, signals depth to the right buyer.

6. **Keep the dark/light theme support** the current diagram has.

## Three-requirement section

Place this after the architecture section. The section header is something like:

> **Why teams choose OpenScope**

Three columns or three stacked blocks. **Important: this is a sequence that builds toward the action broker as the climax, not three co-equal items.** The copy should make the third item feel like the unique value.

### Block 1: Prompt-side data protection

**Header:** `Stop sensitive data from reaching the model`

**Body:** `Engineers paste proprietary code. Agents pull customer records into prompts. Most leaks happen at the input boundary, before anyone reviews what's about to be sent. OpenScope's prompt security layer scrubs PII, credentials, and proprietary IP before any request leaves your environment — running on your infrastructure, never seeing your data leave it.`

### Block 2: Model access without lock-in

**Header:** `Unified model access on your terms`

**Body:** `Route across Claude, GPT, Gemini, or self-hosted models through one API, with your own provider credentials and your own usage limits. No third-party sees your prompts. No token markup. Bring your existing gateway — LiteLLM, Bifrost, or others — or use the one built in.`

### Block 3: Action governance (the climax)

**Header:** `Govern what the agent actually does — this is where most platforms stop`

**Body:** `Capability brokering replaces raw privileged access with scoped, auditable actions. Your agent gets refund_payment(charge_id=…), not your billing database. restart_service(name=…), not shell access. publish_build(version=…), not write access to your release pipeline. And when something goes wrong, an out-of-band circuit breaker pauses the agent fleet immediately, with cryptographic attestation that it stopped.`

Visual treatment: give Block 3 slightly more visual weight (longer, more prominent, or a distinct accent) than Blocks 1 and 2. The asymmetry tells the visitor where the unique value lives.

## "Why OpenScope" callout

Single sentence (or short paragraph) that lives somewhere prominent — ideally between the three-requirement section and the existing "OpenScope Model" section:

> **AI gateways govern what your agents *see*. Capability brokers govern what your agents *do*. OpenScope does both, in one customer-deployed platform, so the trust boundary your security team needs to reason about is one boundary, not two.**

This is the line that converts a buyer mentally evaluating "LiteLLM + something for actions" into evaluating OpenScope as a unified option.

## What to preserve from the current site

The following existing content is working well and should remain, lightly edited if needed:

1. **The "problem is not that agents are evil" section** — keep, possibly tighten. The four icons (production deletion, release checklist failure, literal execution, fast blast radius) communicate the action-side risk story well.

2. **The "OpenScope Model" section** with the brokered action examples (`restart_service`, `publish_build`, `refund_payment`) — keep. This is the most concrete and convincing piece of the current site.

3. **The "Security Difference" / "Execution containment" / "Key containment" sections** — keep. These are technically credible and answer the obvious follow-up questions.

4. **The Use Cases grid** — keep, but define `OpenClaw` and `NemoClaw` inline on first reference (currently they appear without explanation). One-line gloss is enough.

5. **The Quick Start CLI block and Download/GitHub CTAs** — keep. These serve the developer audience and are not in conflict with the enterprise positioning.

## What to remove or de-emphasize

1. **The "Decision Lens" section currently says "Use a gateway for governance, use OpenScope for containment, use both when needed."** This needs to be reframed or removed. As written, it tells the buyer to look elsewhere for half the solution. The new framing positions OpenScope as both halves — so this section should either be deleted or rewritten to position OpenScope as the unified option that also integrates with existing gateways if the customer already has one.

   Suggested rewrite if kept:
   > **Already have an AI gateway? OpenScope integrates with the ones you trust.**
   > LiteLLM, Bifrost, Portkey, or direct provider APIs — OpenScope works with what you already have. The capability broker and circuit breaker work the same way regardless of how prompts flow in.

2. **Reduce the prominence of "capability broker" as the category descriptor in titles and meta tags.** Keep it as a technical term in body copy where it's precise, but the top-level category should read as "AI agent trust perimeter" or "AI agent action control" — terms a CISO might actually search for. Update the `<title>`, meta description, and OG tags accordingly. Suggested:
   - `<title>`: `OpenScope — AI Agent Trust Perimeter`
   - meta description: `Govern what your AI agents see and what they do. Prompt security, scoped capabilities, and a circuit breaker — customer-deployed, open source.`

## Footer

Add a single understated line in the footer (not a marquee section):

> `Built by Cylonix — a team with a track record in open-source infrastructure.`

Link `Cylonix` to https://github.com/cylonix. That's the entire visible mention of Cylonix on the site. No homepage section, no "about us" elevator pitch built around it. Anyone who wants to dig in can click through and find the receipts.

## Enterprise CTA / design partner ask

The primary CTA `Talk to us about a design partnership` should route to either:
- A simple Calendly-style booking page, or
- A short form (name, company, email, "what agent risk are you trying to address?") that creates a real signal of qualified intent.

Avoid a generic "contact us" page. The CTA wording itself is part of the qualification — buyers who self-identify as design-partner-candidates are the ones worth talking to first.

## Out of scope for this revision

These come later, after first design-partner conversations validate messaging:

- Full separate enterprise landing page
- CISO-specific compliance content (SOC 2 mapping, NIST AI RMF, etc.)
- Customer logos / case studies
- Pricing page
- Two-audience routing structure (split developer vs. enterprise paths)

The current homepage with the changes above is sufficient to convert the small number of qualified enterprise visitors expected at this stage. Bigger restructures wait until real buyer language is in hand.

## Acceptance criteria

The revised homepage should pass these checks:

1. **Within 10 seconds of landing, a CISO can identify that this product addresses both prompt-side data risk and action-side blast-radius risk.** The architecture diagram and the first screen of copy together accomplish this.

2. **The action broker is clearly the center of gravity** — not equal billing with the router/DLP side. A buyer should come away understanding "this is primarily an action governance product that also handles prompt security," not "this is a gateway with extra features."

3. **The existing developer audience is not alienated.** GitHub CTA, CLI examples, OSS framing, and download links remain prominent further down the page. A developer landing on the page still recognizes it as their kind of product.

4. **Cylonix is mentioned exactly once, in the footer, with a link.** No more, no less.

5. **There is one clear path for an enterprise prospect to start a conversation** (the design-partnership CTA), and it is above the fold.

## Suggested order of work for Claude Code

1. Update `<title>`, meta description, and OG tags first (small, mechanical).
2. Replace the hero section with the new headline, subhead, and CTAs.
3. Add the "trust perimeter has two halves" section immediately below the hero.
4. Update the three-requirement section (replacing the current problem-framing if it conflicts, or inserting between hero and existing content if it doesn't).
5. Add the "Why OpenScope" one-liner callout.
6. Rework or remove the "Decision Lens" section per notes above.
7. Define OpenClaw/NemoClaw inline on first reference.
8. Add the footer Cylonix line.
9. Update the architecture diagram per the evolution notes (this may be a separate task depending on how the diagram is sourced — SVG edit or designer hand-off).
10. Verify all existing developer-facing content (Quick Start, Download, GitHub, OpenScope Model section, Security Difference section) is preserved.

## Notes for review

Before Claude Code commits, the human should review:

- Whether the headline `Don't trust your agents with raw power. Give them a perimeter.` lands or feels too cute. Alternative: `Govern what your AI agents see — and what they do.` (More descriptive, less punchy.)
- Whether `AI Agent Trust Perimeter` is the right category descriptor. Alternatives: `AI Agent Action Control`, `Agentic Workflow Governance`. The chosen term should appear in the `<title>` and as the eyebrow line.
- Whether to keep the existing "OpenClaw accessing your internal database" hero framing as a secondary callout (it's vivid and developer-resonant) or retire it in favor of the cleaner enterprise framing.
