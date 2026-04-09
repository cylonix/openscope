---
marp: true
theme: default
paginate: true
size: 16:9
title: Why AI Gateways Are Not Enough
description: High-risk agentic workflows need execution containment
author: OpenScope
---

# Why AI Gateways Are Not Enough

## High-Risk Agentic Workflows Need Execution Containment

- AI gateways are valuable
- They solve real governance problems
- But high-risk agentic workflows need more than traffic inspection
- They need a stronger execution boundary

---

# AI Gateways Solve a Real Problem

- Centralized control across many agents and tools
- Model and provider routing
- Org-wide policy and visibility
- Session logging and review
- Fast additive rollout

Example:

- Tailscale Apture is one example of an AI gateway category

---

# The Core Security Difference

![w:1100](./diagrams/filter_vs_scope.svg)

**Key point**

- A gateway inspects access to a raw privileged path
- A brokered-capability model removes the raw privileged path from the agent

---

# The Key Management Difference

![w:1100](./diagrams/where_the_key_lives.svg)

**Key point**

- AI governance is not the same as credential containment
- Stronger requirement: the agent must not possess the key at all

---

# New Risk in Agentic Workflows

## Behavior Can Change Without a Traditional Redeploy

- Traditional enterprise tools change by release and deployment
- Agentic systems can change through:
  - prompt updates
  - tool config changes
  - `SKILL.md` updates
  - runtime instruction changes

**Key point**

- Security can no longer rely only on slow application change cycles

---

# Second New Risk in Agentic Workflows

## Agents Can Probe for Alternate Paths Faster Than Humans

![w:1000](./diagrams/why_bypass_happens.svg)

**Key point**

- A gateway often protects a path
- A capable agent searches for any path that completes the task
- High-risk workflows need a more locked-down approach

---

# When Capability Brokering Becomes Necessary

- Production operations
- SSH-based remediation
- Sensitive databases
- Internal admin APIs
- Endpoint automation
- Finance, support, or customer-impacting actions

**Key point**

- If the system owner does not want the agent to ever hold the raw primitive,
  a brokered-capability layer is the better fit

---

# Recommended Architecture

![w:1050](./diagrams/architecture_difference.svg)

- Use an AI gateway for traffic-plane governance
- Use a brokered-capability layer for execution-plane containment
- Use both when broad governance and strong containment are both required

---

# The Decision Question

Instead of asking:

- Can this product apply policy to tools?

Ask:

- Does this product leave the raw privileged primitive exposed to the agent?

**Final takeaway**

- High-risk agentic workflows need more than AI governance
- They need containment of privileged execution
