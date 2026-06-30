

# Engineering Requirement & Design Document (ERD)**Feature Name:** OpenScope Ephemeral Action Broker & Outbound Streaming Reflector
**Status:** Draft / Technical Proposal
**Author:** Cylonix Engineering
---## 1. Executive Summary & Problem Space### 1.1 The Current "Shadow IT" VulnerabilityWhen enterprise engineering teams collaborate across organizational boundaries during high-stakes operational incidents or debugging sprints, they hit a strict security bottleneck. External vendor agents and contractor operators lack access to the internal network infrastructure. 

To unblock work quickly, developers routinely resort to two high-risk "Shadow IT" workflows:1. **The Static Data Leak (Gists/Pastebin):** Developers manually copy-paste raw terminal logs, infrastructure schemas, and stack traces into unmonitored text bins to supply external agents with diagnostic context. This leaves sensitive environment keys and IP exposed at rest on the public web.
2. **The Ambient Shell Leak (VPN/SSH Ingress):** If live interaction is mandatory, IT is pressured to provision temporary credentials that pierce the corporate network perimeter. This grants the external operator full, unstructured shell access. Autonomous agents inherit broad "ambient authority," allowing them to run unauthorized commands (`cat`, `rm -rf`, `ls`), traverse lateral services, and exfiltrate source modules.
### 1.2 The OpenScope Structural SolutionThis feature introduces an **Action Broker & Outbound Streaming Reflector Architecture** that completely decouples operational execution capabilities from data-access visibility. 

Instead of opening inbound firewall ports or posting files to public clouds, an internal developer uses the OpenScope CLI to register an ephemeral **Capability Passport**. The local OpenScope daemon establishes a secure, outbound-only tunnel to an external, untrusted **Reflector Proxy**. 

External human engineers and robot agents can interactively execute specific, pre-sanctioned debugging verbs (e.g., `service.restart`, `db.diagnose`) and stream live log outputs on-demand. However, they remain structurally isolated from the network underlay, lack a terminal shell environment, and are physically blinded to environmental credentials and raw files—delivering absolute Data Loss Prevention (DLP) by design.
---## 2. Core Functional Requirements*   **R-1: Zero Inbound Ingress:** The local OpenScope daemon must establish connectivity to the external Reflector exclusively via outbound network pipes (HTTPS/WSS/gRPC). It must require zero incoming open firewall ports or network edge modifications within the host enterprise environment.*   **R-2: Client-Side Ephemeral Passports:** The CLI must generate a highly compact, cryptographically signed configuration token ("Passport") locally. This payload must utilize an asynchronous transport mechanism (like SimpleX Messaging Protocol / SMP) to register with the remote agent without exposing connection keys to the central relay server.*   **R-3: Deterministic Verb-Scoping:** The execution framework must enforce a strict default-deny policy model. The external operator may only execute a precise array of pre-approved commands outlined within a local policy manifest file.*   **R-4: Automated Parameter Sanitization:** The broker must intercept, tokenize, and validate all input arguments and flags passed by the external agent *prior* to executing the routine on the local host, dropping the stream instantly if shell injection or path traversal attempts are detected.*   **R-5: Zero-Knowledge Metadata Relay:** The central proxy infrastructure routing the connection must operate purely as a blind data reflector. All data passing through the tunnel must be encrypted locally using an asymmetric key pair held exclusively by the external client, preventing the reflector from reading or archiving internal logs in plaintext.*   **R-6: Autonomous Session Tearing:** The outbound streaming tunnel must automatically self-destruct upon the fulfillment of its designated command loop, meeting an explicit maximum TTL constraint (defaulting to 30 minutes) to eliminate persistent access vectors.
---## 3. High-Level Architectural Flow

[ COMPANY A PROTECTED NETWORK ] [ EXTERNAL PUBLIC ENVIRONMENT ]
( Firewall Ports Closed Natively )
+------------------+ +------------------+
| Host Server | | Local OpenScope |
| (Staging / Prod) | ◄───+ Daemon |
+------------------+ +--------+---------+
|
(Outbound WSS / gRPC Tunnel)
|
▼
+--------------------+
| OpenScope Public |
| Streaming REFL | ◄─────────+ [ External Operator / Agent B ]
| (Zero-Knowledge) | | - Passes Signed Token
+--------------------+ | - Executes service.restart
| - Streams Scoped Telemetry
+─── ❌ No Shell / No Ingress / No Data Access


---

## 4. Technical Design & Implementation Details

### 4.1 The Capability Passport Schema
The passport is generated locally on the developer's terminal as a JSON web container, packed with cryptographic constraints. It dictates what the external agent can do and how it talks back to the reflector server.

```json
{
  "passport_id": "osp_9823fbc21a44e",
  "issuer_org": "company_a",
  "target_reflector": "://openscopeai.com",
  "target_identity_fingerprint": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "valid_until": "2026-06-26T21:52:22Z",
  "sanctioned_capabilities": [
    {
      "verb": "service.restart",
      "allowed_parameters": {
        "service_name": ["billing-staging", "auth-v2-staging"]
      }
    },
    {
      "verb": "telemetry.stream_logs",
      "allowed_parameters": {
        "log_path": ["/var/log/nginx/error.log"],
        "max_lines_per_second": 250
      }
    }
  ]
}
```

### 4.2 The Local Action Broker Configuration (`policy.yaml`)
The local daemon evaluates inbound streaming commands against a hard-coded static YAML manifest locked down on the target machine. This configuration completely strips away the agent's ability to inject custom execution flags or navigate directories.

```yaml
version: "openscope/v1alpha"
metadata:
  name: "vendor-debugging-bounds"
engine:
  enforce_strict_arguments: true

bounds:
  - verb: "service.restart"
    handler: "/usr/bin/systemctl restart {{.service_name}}"
    validation:
      service_name: "^[a-zA-Z0-9\\-]+-staging\$"

  - verb: "telemetry.stream_logs"
    handler: "/usr/bin/tail -f {{.log_path}}"
    validation:
      log_path: "^/var/log/(nginx|syslog)/[a-zA-Z0-9\\-_\\.]+\\.log\$"
```

### 4.3 Outbound Streaming and Connection Lifecycle
1. **Instantiation:** The local developer executes `openscope share --config policy.yaml --to vendor-b`. 
2. **Tunnel Negotiation:** The local daemon dials out via an asymmetric HTTP/2 or gRPC wrapper to `://openscopeai.com`. It holds open a stateful, reverse-proxy piping connection.
3. **The URL Fragment Cryptographic Trick:** The tool outputs a link containing the passport payload string and an appended encryption secret separated by a URL hash (`#`).
   * Example: `https://openscopeai.com`
   * *Security Note:* The decryption token past the `#` character is structurally dropped by the browser/HTTP transport layer and **never reaches the OpenScope Reflector database**, upholding client-side Zero-Knowledge integrity.
4. **Execution Iteration:** When External Agent B pushes a request payload to the Reflector, the Reflector forwards the message block down the outbound-established WebSocket lane. The local daemon verifies the cryptographic signature against the local keys, validates the parameters, safely wraps the command inside the native OS runtime environment, and streams the outputs back up the channel.

---

## 5. Security & Structural Data Loss Prevention (DLP) Analysis

*   **Immunity to Text Obfuscation:** Traditional DLP firewalls parse LLM output fields looking for patterns like base64-encoded strings or regex matches of credentials. Because OpenScope strips away the agent's ability to invoke native file inspection commands (`cat`, `grep`, `less`), the agent is structurally blinded from seeing system credentials in the first place, completely removing the reliance on fragile heuristic scanners.
*   **Containment of Lateral Network Traversal:** Because the external agent operates out-of-band via an encapsulated message pipe directed strictly to the daemon, it does not exist on an internal subnet or underlay network layer. It can neither discover neighboring network endpoints nor exploit flaws in adjacent company enterprise microservices.
*   **Data at Rest Elimination:** The data transit design utilizes purely in-memory streaming pipelines. The Reflector server drops byte arrays the millisecond they are flushed out to the client agent, eliminating files at rest on third-party cloud infrastructure and minimizing the company’s structural compliance risk profile.

---

## 6. Future Roadmap Considerations
*   **Native Model Context Protocol (MCP) Integration:** Package the client-side validation logic directly as an autonomous MCP Server package plugin so terminal environments (like *Claude Code*) can handle the passport handshake natively without external script layers.
*   **Asymmetric Compliance Audit Vaulting:** Build a sub-feature that outputs an end-to-end encrypted action journal on the local daemon machine. The journal is automatically sealed with the enterprise SOC's master corporate public security key, giving governance teams an unalterable post-mortem record without leaking telemetry metadata to developers.



