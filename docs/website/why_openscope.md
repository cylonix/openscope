# Why OpenScope Page Brief

Design and generate the `Why OpenScope` page.

## Page Goal

This page should explain the strategic argument for OpenScope:

- why AI gateways are useful but insufficient for high-risk workflows
- why execution containment matters
- why key containment matters
- why adaptive agents change the threat model

## Hero

### Headline

`Why OpenScope`

### Subheadline

`Because high-risk agent workflows need more than traffic governance. They need execution containment.`

### Intro Copy

`Enterprise teams often start with AI governance: which models are allowed, which tools are allowed, and how behavior gets logged. Those are important controls. OpenScope addresses the deeper question: what is the actual execution boundary for privileged actions?`

## Section: Gateways Solve a Real Problem

### Body

`AI gateways are valuable. They centralize routing, policy, visibility, and review across many agents and tools. For broad AI adoption, that is a sensible first step. But a gateway mainly governs traffic paths. It does not automatically remove the dangerous primitive from the agent runtime.`

### Supporting Bullets

- `Centralized control across many agents and tools`
- `Model and provider routing`
- `Org-wide policy and visibility`
- `Session logging and review`
- `Fast additive rollout`

## Section: The Core Security Difference

### Headline

`Filtering a raw path is not the same as removing it.`

### Body

`The gateway model says: the agent may try to use a raw privileged tool, and we will inspect that path. The brokered-capability model says: the agent never gets the raw privileged tool in the first place. It only gets a smaller approved capability.`

### Diagram

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

## Section: The Key Management Difference

### Body

`Many teams want stronger assurance than tool filtering alone. They want proof that the agent never held the key, token, or broad permission at all. OpenScope is designed for that stricter trust model. The key stays inside the broker.`

### Diagram

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

## Section: Why Agentic Workflows Change the Security Equation

### Subsection: Behavior Can Change Without a Traditional Redeploy

Body:

`Traditional enterprise tools usually change through release and deployment. Agentic systems can change through prompts, tool config, runtime instructions, and skill updates. The effective access pattern can shift much faster than security teams expect.`

### Subsection: Agents Search for Alternate Paths

Body:

`A gateway often protects a path. A capable agent searches for any path that completes the task. This is not necessarily malicious behavior. It is often goal-seeking behavior. That is exactly why removing the raw primitive becomes more attractive than trying to perfectly inspect every possible route.`

### Diagram

```mermaid
flowchart LR
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

    subgraph R["OpenScope / Brokered Capability"]
        direction TB
        N2["No raw privileged interface exposed"]:::greenNote
        A2["Scoped action only"]:::greenNode
        B2["Smaller attack surface"]:::greenNode
        C2["Harder to bypass"]:::greenNode
        A2 --> B2
        B2 --> C2
    end

    classDef redNote fill:#fff1f1,stroke:#e57373,stroke-width:1px,color:#8a1c1c;
    classDef greenNote fill:#eef9ee,stroke:#66bb6a,stroke-width:1px,color:#1b5e20;
    classDef redNode fill:#ffd9d9,stroke:#c62828,stroke-width:2px,color:#111;
    classDef greenNode fill:#d9f7d6,stroke:#2e7d32,stroke-width:2px,color:#111;
    style L fill:transparent,stroke:#cbd5e1,stroke-width:1px
    style R fill:transparent,stroke:#cbd5e1,stroke-width:1px
```

## Section: Decision Frame

### Headline

`Ask a better question`

### Copy

`Instead of asking whether a product can apply policy to tools, ask whether it leaves the raw privileged primitive exposed to the agent. That is the cleaner dividing line between traffic governance and true execution containment.`

## Final CTA

- `Download OpenScope`
- `View Code`

