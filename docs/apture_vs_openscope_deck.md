# Apture vs OpenScope Security Positioning

## Slide 1: Filter Raw Privilege vs Expose Only Scoped Access

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

    linkStyle 0 stroke:#c62828,stroke-width:3px,color:#c62828
    linkStyle 1 stroke:#c62828,stroke-width:3px,color:#c62828
    linkStyle 3 stroke:#c62828,stroke-width:3px,color:#c62828
    linkStyle 4 stroke:#2e7d32,stroke-width:3px,color:#2e7d32
    linkStyle 5 stroke:#2e7d32,stroke-width:3px,color:#2e7d32
    linkStyle 6 stroke:#c62828,stroke-width:3px,color:#c62828

    classDef redNote fill:#fff1f1,stroke:#e57373,stroke-width:1px,color:#8a1c1c;
    classDef greenNote fill:#eef9ee,stroke:#66bb6a,stroke-width:1px,color:#1b5e20;
    classDef redNode fill:#ffd9d9,stroke:#c62828,stroke-width:2px,color:#111;
    classDef greenNode fill:#d9f7d6,stroke:#2e7d32,stroke-width:2px,color:#111;
    classDef neutral fill:#f7f9fc,stroke:#90a4ae,stroke-width:1.5px,color:#111;
```

Caption: A gateway decides whether an agent may use a raw privileged tool. OpenScope never exposes that raw tool at all.

## Slide 2: Where The Key Lives

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

    linkStyle 0 stroke:#c62828,stroke-width:3px,color:#c62828
    linkStyle 1 stroke:#c62828,stroke-width:3px,color:#c62828
    linkStyle 2 stroke:#c62828,stroke-width:3px,color:#c62828
    linkStyle 3 stroke:#2e7d32,stroke-width:3px,color:#2e7d32
    linkStyle 4 stroke:#2e7d32,stroke-width:3px,color:#2e7d32
    linkStyle 5 stroke:#c62828,stroke-width:3px,color:#c62828

    classDef redNote fill:#fff1f1,stroke:#e57373,stroke-width:1px,color:#8a1c1c;
    classDef greenNote fill:#eef9ee,stroke:#66bb6a,stroke-width:1px,color:#1b5e20;
    classDef redNode fill:#ffd9d9,stroke:#c62828,stroke-width:2px,color:#111;
    classDef greenNode fill:#d9f7d6,stroke:#2e7d32,stroke-width:2px,color:#111;
    classDef neutral fill:#f7f9fc,stroke:#90a4ae,stroke-width:1.5px,color:#111;
```

Caption: Filtering can govern requests, but the raw credentialed path still exists. OpenScope keeps the key inside the broker.

## Slide 3: Why Bypass Happens

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
```

Caption: Gateways must keep every path in-band. OpenScope reduces bypass risk by removing the raw privileged primitive.

## Slide 4: Architecture Difference

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
```

Caption: Gateways govern access to raw tools. OpenScope transforms privileged systems into narrow, auditable capabilities.
