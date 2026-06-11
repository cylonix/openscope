-- 0004_tenant_budgets.sql
--
-- Per-tenant monthly budget override. NULL means the tenant uses the
-- deployment-wide default (OPENSCOPE_DEFAULT_MONTHLY_BUDGET_USD env on the
-- router). The router-side soft cap (billing.CheckMonthlyCap) reads this
-- column; any cloud-side hard cap (e.g. AWS Budgets + IAM deny) remains an
-- independent second layer.

ALTER TABLE app.tenants
    ADD COLUMN IF NOT EXISTS monthly_budget_usd NUMERIC(10, 2);

COMMENT ON COLUMN app.tenants.monthly_budget_usd IS
    'Per-tenant monthly spend cap in USD; NULL = deployment default';
