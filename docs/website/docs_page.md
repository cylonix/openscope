# Docs Page Brief

Design and generate the `Docs` page.

## Page Goal

Provide a structured, self-explanatory docs landing page for OpenScope that helps visitors understand what to read first even if external docs are not fetched dynamically.

This page should not feel like a generic blog index. It should feel like a product documentation gateway.

## Hero

### Headline

`OpenScope Docs`

### Subheadline

`Architecture, setup, integrations, and operational guidance for brokered agent access.`

### Intro Copy

`OpenScope is easiest to understand when the docs are grouped by intent: start here, understand the architecture, extend it safely, and validate it in practice.`

## Section: Get Started

Render as a card grid.

### Card 1

Title:

`README`

Description:

`Start with the core architecture, CLI model, quick start, commands, policy model, and configuration layout.`

### Card 2

Title:

`OpenClaw workflow`

Description:

`Understand how OpenScope fits into the local OpenClaw workflow and why brokered actions are safer than raw local automation access.`

### Card 3

Title:

`NemoClaw install`

Description:

`Learn the client-only sandbox model, where the broker stays on the host and the sandbox uses a narrow client surface.`

## Section: Architecture

### Intro Copy

`These docs explain the conceptual model behind OpenScope: capability brokering, key containment, bypass resistance, and how OpenScope fits alongside gateways and other security controls.`

### Cards

- `Enterprise security model`
  Description: `Why AI gateways are not enough for high-risk workflows and where capability brokering becomes necessary.`
- `OpenScope diagrams`
  Description: `Compact visual explanations for architecture difference, bypass risk, execution containment, and key containment.`
- `Cylonix + OpenScope architecture`
  Description: `How OpenScope fits into the wider secure-reach plus brokered-action model.`

### Embedded Architecture Diagram

```mermaid
flowchart LR
    A["AI agent"] --> B["OpenScope CLI"]
    B --> C["Broker daemon"]
    C --> D["Executor"]
    D --> E["Sensitive system"]
    F["Policy"] --> C
    G["Audit"] <-- C
    H["Credential / permission"] --> C

    classDef broker fill:#d9f7d6,stroke:#2e7d32,stroke-width:2px,color:#111;
    classDef neutral fill:#f7f9fc,stroke:#90a4ae,stroke-width:1.5px,color:#111;
    class C broker
    class A,B,D,E,F,G,H neutral
```

## Section: Integration Guides

### Intro Copy

`OpenScope can broker both local app actions and external system actions through the same trust model.`

### Cards

- `Jira over HTTP`
  Description: `Keep the Jira token in a broker-owned HTTP profile while exposing narrow actions like get issue and search issues.`
- `SSH target validation`
  Description: `Use named targets, scoped services, and explicit policy for SSH-backed operations.`
- `Custom app manifests`
  Description: `Define new app actions in YAML with action-level parameters and outputs.`

## Section: Packaging and Operations

### Intro Copy

`OpenScope has operational concerns that matter for real deployment: signed runtime packaging, broker startup, validation, and pilot readiness.`

### Cards

- `Packaging and signing`
  Description: `Signed macOS packaging, LaunchAgent layout, and installer shape.`
- `Local validation runbook`
  Description: `Shared validation flows across packaged installs, OpenClaw, NemoClaw, and SSH paths.`
- `Pilot guidance`
  Description: `Operational guidance for early rollout and validation.`

## Section: Suggested Reading Order

Render this as a visual timeline or numbered sequence.

1. `Start with the README`
2. `Read the architecture overview`
3. `Understand why OpenScope differs from a gateway`
4. `Review one integration guide`
5. `Use the validation runbook to test the setup`

## Section: Documentation CTA

### Copy

`Want the full source and current docs tree? Browse the repository directly on GitHub.`

### Buttons

- `View Code`
- `Download OpenScope`

