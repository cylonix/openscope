# Bedrock IAM Pattern (reference)

The router's Bedrock provider assumes a role in a **separate AWS account**
per deployment, with an external ID. This documents the pattern so you can
reproduce it with your own IaC; OpenScope does not ship account-management
scripts.

```
router host (account A)                bedrock account (account B)
RouterInstanceRole  --sts:AssumeRole-->  RouterInvokeRole
        + ExternalID                       └─ bedrock:Converse on an
                                              explicit model allowlist
```

## RouterInvokeRole (account B) — trust policy

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_A>:role/RouterInstanceRole"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "<EXTERNAL_ID>"}}
  }]
}
```

## RouterInvokeRole — permissions (model allowlist)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["bedrock:InvokeModel", "bedrock:Converse"],
    "Resource": [
      "arn:aws:bedrock:*:<ACCOUNT_B>:inference-profile/us.anthropic.claude-haiku-4-5-*",
      "arn:aws:bedrock:*::foundation-model/*"
    ]
  }]
}
```

Router env:

```
OPENSCOPE_BEDROCK_INVOKE_ROLE_ARN=arn:aws:iam::<ACCOUNT_B>:role/RouterInvokeRole
OPENSCOPE_BEDROCK_EXTERNAL_ID=<EXTERNAL_ID>
OPENSCOPE_BEDROCK_REGION=us-west-2
```

The router uses 15-minute STS sessions, auto-refreshed; no long-lived
Bedrock credentials exist on the router host.

## Recommended hardening in account B

- **Deny prompt logging** (SCP or IAM): deny
  `bedrock:PutModelInvocationLoggingConfiguration` and friends so prompt
  bodies can never be captured cloud-side.
- **Hard budget cap**: AWS Budgets action that attaches an explicit-deny
  policy to RouterInvokeRole at your spend threshold. This is Layer 2;
  the router's own per-tenant soft cap (`monthly_budget_usd`) is Layer 1.
- **Kill switch**: a role allowed only to detach/attach that deny policy —
  instant, out-of-band revocation of all model access.
