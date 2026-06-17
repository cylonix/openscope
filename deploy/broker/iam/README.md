# SSM executor — IAM contract (Phase 4)

The `ssm` executor reaches EC2 instances over Systems Manager with no SSH and no
SSH key. Its safety rests on a two-part IAM contract; OpenScope's `plan`
(`SSM-DEPLOY-CONTRACT`) reminds you of it but cannot verify it, because it lives
in AWS, not in the proposal.

## The invariant

The credential that can run SSM (`ssm:SendCommand` / `StartSession`) must be held
**only by the broker**, and the broker's credential must be agent-unreadable.
Equivalently: the **agent's own AWS identity must be denied SSM**. Custody of the
broker's credential is necessary but not sufficient — denying the agent is the
binding control (an agent that can `aws ssm send-command` itself ignores the
broker entirely; the executor's `credaudit` and the guard hook only raise the
bar). This is airtight only in the remote-agent topology, where the agent holds
no AWS identity in the target account at all.

## What to apply

| File | What it is | Where it goes |
|---|---|---|
| `broker-ssm-role.policy.json` | least-privilege **allow** — `SendCommand` (AWS-RunShellScript) to instances tagged `openscope-target=true`, plus reading results | the broker's identity: the **EC2 instance role** on the broker host (preferred — no static secret), or a dedicated role whose creds are root-owned (`/var/openscope/aws/credentials`, referenced by `AWS_SHARED_CREDENTIALS_FILE` in the daemon env) |
| `agent-ssm-deny.policy.json` | **deny** all SSM execution + document tampering | the **agent's** IAM role/user, as a **permission boundary** |

Tag the instances the broker may reach: `openscope-target=true`. Tighter still,
pin a custom SSM document and replace the `BrokerUseRunShellScript` statement so
IAM can forbid `AWS-RunShellScript` outright.

### Permission boundary (recommended)

Attach `agent-ssm-deny.policy.json` as a permission boundary on the agent's IAM
principal. The broker role does not carry the boundary, so it keeps SSM. Simple
and self-contained per identity.

### Org-wide SCP (alternative)

To deny SSM across whole accounts/OUs instead, use the deny as an SCP but **exempt
the broker role**, or you'll deny the broker too:

```json
"Condition": {
  "StringNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/OpenScopeBrokerRole" }
}
```

Add that `Condition` to the `DenyAgentSSMExecution` statement when attaching as an
SCP (replace `OpenScopeBrokerRole` with the broker's role name).

## Co-located agents (IMDS)

If an agent process runs on the broker host itself, it can reach the instance
role via IMDS and bypass the deny. Lock IMDS to root (IMDSv2 + a hop limit of 1 +
an iptables owner-match dropping non-root access to `169.254.169.254`). In the
remote-agent topology the agent never runs on the broker host, so this does not
arise.

## Defense in depth (not the boundary)

The Claude Code guard hook (`docs/examples/claude-code/openscope-guard.sh`) denies
raw `aws ssm send-command` / `start-session` and `ssh i-…` from the agent and
redirects to `openscope ssm …`. It catches CLI bypass and accidents but cannot
intercept the AWS SDK / boto3 — which is why the IAM deny above is the real
control.
