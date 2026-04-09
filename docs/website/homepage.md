# OpenScope Homepage Brief

Design and generate the `open-scope.org` homepage.

## Page Goal

The homepage should make three things obvious in the first screen:

1. OpenScope is a capability broker for AI agents.
2. It is different from a gateway because it removes raw privileged paths.
3. Visitors can immediately view the code or download a release.

## Required Links

- Repo: `https://github.com/cylonix/openscope`
- Releases: `https://github.com/cylonix/openscope/releases`

## Hero

### Eyebrow

`Scoped, auditable agent access`

### Headline

`Don’t give AI agents raw power. Give them scoped capabilities.`

### Supporting Copy

`OpenScope is a capability broker that turns raw privileged access into narrow, policy-bound actions. Keep keys inside the broker. Remove raw interfaces from the agent path. Audit every decision.`

### Primary CTA

`Download OpenScope`

Links to:

`https://github.com/cylonix/openscope/releases`

### Secondary CTA

`View Code`

Links to:

`https://github.com/cylonix/openscope`

### Meta Strip

- `Open source`
- `Policy-bound actions`
- `Key containment by design`
- `Built for high-risk workflows`

### Hero Visual Requirement

Use a premium right-column panel that renders this Mermaid diagram or a polished visual based on it:

```mermaid
flowchart LR
    subgraph L["Gateway / Filtering"]
        direction LR
        A1["Agent"]:::neutral
        G1["Inline gateway"]:::neutral
        T1["Raw tool / MCP / API"]:::redNode
        R1["Sensitive system"]:::neutral
        A1 --> G1
        G1 --> T1
        T1 --> R1
    end

    subgraph R["OpenScope / Brokered Capability"]
        direction LR
        A2["Agent"]:::neutral
        B2["OpenScope broker"]:::greenNode
        C2["Scoped capability<br/>read_note / restart_service / refund_payment"]:::greenNode
        R2["Sensitive system"]:::neutral
        A2 --> B2
        B2 --> C2
        C2 --> R2
    end

    X1["Inspect and filter raw power"]:::redNote
    X2["Contain keys and expose narrow actions"]:::greenNote

    L --> X1
    R --> X2

    classDef redNote fill:#fff1f1,stroke:#e57373,stroke-width:1px,color:#8a1c1c;
    classDef greenNote fill:#eef9ee,stroke:#66bb6a,stroke-width:1px,color:#1b5e20;
    classDef redNode fill:#ffd9d9,stroke:#c62828,stroke-width:2px,color:#111;
    classDef greenNode fill:#d9f7d6,stroke:#2e7d32,stroke-width:2px,color:#111;
    classDef neutral fill:#f7f9fc,stroke:#90a4ae,stroke-width:1.5px,color:#111;
    style L fill:transparent,stroke:#cbd5e1,stroke-width:1px
    style R fill:transparent,stroke:#cbd5e1,stroke-width:1px
```

## Section: Why OpenScope

### Section Headline

`AI gateways help. High-risk workflows still need stronger containment.`

### Copy

`AI gateways improve governance, visibility, and routing. But when the raw privileged primitive still exists, adaptive agents can search for alternate paths. OpenScope is built for the stricter requirement: the agent should not receive the raw privileged path in the first place.`

### Supporting Points

- `Agents can change behavior without a normal redeploy`
- `Prompt and config changes can alter access patterns fast`
- `Adaptive agents search for alternate paths`
- `Coverage-dependent filtering is weaker when the actor is goal-seeking`

### Visual

Render or interpret this Mermaid:

```mermaid
flowchart TB
    subgraph L["Gateway / Filtering"]
        direction TB
        N1["Security depends on complete coverage"]:::redNote
        A1["Raw tool"]:::redNode
        B1["Alternate path"]:::redNode
        C1["Side channel"]:::redNode
        D1["Bypass risk"]:::redNode
        A1 --> D1
        B1 --> D1
        C1 --> D1
    end

    classDef redNote fill:#fff1f1,stroke:#e57373,stroke-width:1px,color:#8a1c1c;
    classDef redNode fill:#ffd9d9,stroke:#c62828,stroke-width:2px,color:#111;
    style L fill:transparent,stroke:#cbd5e1,stroke-width:1px
```

## Section: The OpenScope Model

### Headline

`Contain keys. Remove raw powers. Expose only approved actions.`

### Copy

`OpenScope places a broker between the agent and the sensitive system. Instead of raw tools, the agent receives explicit actions such as reading a note, restarting a service, or refunding a payment. Policy is enforced at the action and parameter level.`

### Capability Example

```text
read_note(folder="Work")
restart_service(service="api")
refund_payment(charge_id="...")
```

### Visual

```mermaid
flowchart TB
    subgraph R["OpenScope / Brokered Capability"]
        direction TB
        N2["No raw privileged interface exposed"]:::greenNote
        A2["Scoped action only"]:::greenNode
        B2["Smaller attack surface"]:::greenNode
        C2["Harder to bypass"]:::greenNode
        A2 --> B2
        B2 --> C2
    end

    classDef greenNote fill:#eef9ee,stroke:#66bb6a,stroke-width:1px,color:#1b5e20;
    classDef greenNode fill:#d9f7d6,stroke:#2e7d32,stroke-width:2px,color:#111;
    style R fill:transparent,stroke:#cbd5e1,stroke-width:1px
```

## Section: The Security Difference

Use a two-card layout.

### Card 1

Title:

`Execution containment`

Body:

`A gateway inspects access to a raw privileged path. A brokered-capability model removes that raw path from the agent entirely.`

Visual:

```mermaid
flowchart LR
    subgraph L["Gateway / Filtering"]
        direction LR
        subgraph LA[" "]
            direction TB
            N1["Raw privileged path<br/>exposed"]:::redNote
            A1["Agent"]:::neutral
        end
        G1{"Permit / Deny"}:::neutral
        T1["Raw privileged tool"]:::redNode
        R1["Sensitive system"]:::neutral
        X1["Blocked"]:::neutral
        A1 --> G1
        G1 -->|Permit| T1
        G1 -.->|Deny| X1
        T1 --> R1
    end

    subgraph R["OpenScope / Brokered Capability"]
        direction LR
        subgraph RA[" "]
            direction TB
            N2["Only scoped access<br/>exposed"]:::greenNote
            A2["Agent"]:::neutral
        end
        O1{"Scoped or unscoped?"}:::neutral
        S2["Scoped action"]:::greenNode
        X2["Unscoped access<br/>not exposed"]:::neutral
        R2["Sensitive system"]:::neutral
        A2 --> O1
        O1 -->|Scoped| S2
        O1 -.->|Unscoped| X2
        S2 --> R2
    end

    classDef redNote fill:#fff1f1,stroke:#e57373,stroke-width:1px,color:#8a1c1c;
    classDef greenNote fill:#eef9ee,stroke:#66bb6a,stroke-width:1px,color:#1b5e20;
    classDef redNode fill:#ffd9d9,stroke:#c62828,stroke-width:2px,color:#111;
    classDef greenNode fill:#d9f7d6,stroke:#2e7d32,stroke-width:2px,color:#111;
    classDef neutral fill:#f7f9fc,stroke:#90a4ae,stroke-width:1.5px,color:#111;
    style L fill:transparent,stroke:#cbd5e1,stroke-width:1px
    style R fill:transparent,stroke:#cbd5e1,stroke-width:1px
    style LA fill:transparent,stroke:transparent
    style RA fill:transparent,stroke:transparent
```

### Card 2

Title:

`Key containment`

Body:

`For high-risk systems, the stronger requirement is that the agent never possesses the key or broad permission at all. OpenScope keeps the key inside the broker.`

Visual:

```mermaid
flowchart LR
    subgraph L["Gateway / Filtering"]
        direction LR
        subgraph LA[" "]
            direction TB
            N1["Key can still be reached<br/>through raw tool path"]:::redNote
            A1["Agent"]:::neutral
        end
        T1["Raw privileged tool"]:::redNode
        K1["Key / secret / permission"]:::redNode
        R1["Sensitive system"]:::neutral
        A1 --> T1
        K1 --> T1
        T1 --> R1
    end

    subgraph R["OpenScope / Brokered Capability"]
        direction LR
        subgraph RA[" "]
            direction TB
            N2["Key stays inside broker"]:::greenNote
            A2["Agent"]:::neutral
        end
        B2["OpenScope broker"]:::greenNode
        K2["Key / secret / permission"]:::greenNode
        R2["Sensitive system"]:::neutral
        A2 --> B2
        K2 --> B2
        B2 --> R2
    end

    classDef redNote fill:#fff1f1,stroke:#e57373,stroke-width:1px,color:#8a1c1c;
    classDef greenNote fill:#eef9ee,stroke:#66bb6a,stroke-width:1px,color:#1b5e20;
    classDef redNode fill:#ffd9d9,stroke:#c62828,stroke-width:2px,color:#111;
    classDef greenNode fill:#d9f7d6,stroke:#2e7d32,stroke-width:2px,color:#111;
    classDef neutral fill:#f7f9fc,stroke:#90a4ae,stroke-width:1.5px,color:#111;
    style L fill:transparent,stroke:#cbd5e1,stroke-width:1px
    style R fill:transparent,stroke:#cbd5e1,stroke-width:1px
    style LA fill:transparent,stroke:transparent
    style RA fill:transparent,stroke:transparent
```

## Section: Use Cases

### Headline

`Where capability brokering becomes necessary`

### Supporting Line

`Best fit when the system owner does not want the agent to ever hold the raw primitive.`

### Cards

- `Production operations`
- `SSH-based remediation`
- `Sensitive databases`
- `Internal admin APIs`
- `Endpoint automation`
- `Finance and support actions`
- `OpenClaw on macOS`
- `Sandboxed NemoClaw`
- `Brokered Jira and SSH extensions`

## Section: Compare

Use a responsive comparison table.

### Columns

- `Product`
- `Best at`
- `Limitation vs OpenScope`

### Rows

- `Tailscale Apture | AI gateway, routing, logging, centralized policy | Governs traffic, but does not remove raw privileged paths`
- `BlueRock | Runtime security, sandboxing, guardrails | Strong runtime control, less focused on predefined scoped capabilities`
- `MintMCP | MCP gateway, role-based tool exposure | Curates MCP access, but is still closer to gateway infrastructure`
- `Peta / Agent Vault | Secret containment | Keeps keys away from agents, but does not fully define scoped action surfaces`
- `OpenScope | Privileged capability brokering | Best fit when agents should never hold the raw primitive`

Highlight the OpenScope row.

## Section: Developer Action

Create three cards.

### Card 1

Title:

`Read the source`

Body:

`Inspect the broker model, policy system, daemon, and integrations directly on GitHub.`

CTA:

`View repository`

### Card 2

Title:

`Download OpenScope`

Body:

`Get the latest release packages and installation assets from GitHub Releases.`

CTA:

`Download latest release`

### Card 3

Title:

`Quick start`

Code:

```bash
openscope status
openscope notes list_notes --agent openclaw --folder Work
openscope notes read_note --agent openclaw --folder Work --note "My Note"
```

Caption:

`OpenScope brokers protected actions through a daemon instead of handing raw privileged access to the agent.`

## Final CTA

### Headline

`Don’t just watch privileged paths. Replace them with scoped capabilities.`

### Body

`Use gateways for broad governance. Use OpenScope where bypass resistance and key containment matter.`

### Buttons

- `Download OpenScope`
- `View Code on GitHub`

### Closing Question

`Do you leave the raw privileged primitive exposed to the agent?`

