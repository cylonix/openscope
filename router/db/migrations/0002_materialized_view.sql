-- 0002_materialized_view.sql — vendor schema aggregates for engineer dashboard.
--
-- The engineer dashboard reads this view. It contains no prompt or response bodies —
-- the only fields are cross-tenant counts, tokens, and dollar costs.

BEGIN;

CREATE MATERIALIZED VIEW vendor.tenant_usage_daily AS
SELECT
  u.tenant_id,
  t.slug                              AS tenant_slug,
  date_trunc('day', u.ts)::date       AS day,
  count(*)                            AS requests,
  sum(u.input_tokens)::bigint         AS input_tokens,
  sum(u.output_tokens)::bigint        AS output_tokens,
  sum(u.total_cost_usd)::numeric(14,6) AS total_cost_usd
FROM app.usage_metrics u
JOIN app.tenants       t ON t.id = u.tenant_id
GROUP BY u.tenant_id, t.slug, date_trunc('day', u.ts)
WITH NO DATA;  -- populated by the first explicit REFRESH

CREATE UNIQUE INDEX tenant_usage_daily_pk
  ON vendor.tenant_usage_daily (tenant_id, day);

-- Concurrent refresh requires the unique index above.
-- Refresh cadence: every 5 min via pg_cron in production, on-demand locally.

GRANT SELECT ON vendor.tenant_usage_daily TO vendor_reader, tenant_reader, app_rw;

COMMIT;
