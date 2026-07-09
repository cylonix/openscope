-- 0005_budget_reservations.sql
--
-- Ephemeral admission-control reservations for the Layer-1 monthly budget.
-- Each in-flight /v1/chat holds a reservation for its estimated max cost while
-- it runs; the cap check (store.ReserveBudget) counts committed usage_metrics
-- PLUS active reservations, so concurrent requests can no longer all read the
-- same under-cap total and overshoot the cap.
--
-- Reservations are admission-only: they never enter usage_metrics/receipts, are
-- deleted once the real usage is recorded, and self-expire after a few minutes.
-- So a crash between reserve and release can only make the cap briefly
-- conservative, never over-charge real billing.

CREATE TABLE IF NOT EXISTS app.budget_reservations (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL,
    est_cost_usd double precision NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS budget_reservations_tenant_idx
    ON app.budget_reservations (tenant_id, created_at);

-- 0001's ALTER DEFAULT PRIVILEGES grants SELECT/INSERT/UPDATE to app_rw for new
-- app tables; admission control also DELETEs (release + expiry GC).
GRANT DELETE ON app.budget_reservations TO app_rw;

-- Internal table: no reader role is granted access, and RLS default-denies any
-- non-BYPASSRLS role (no policy = deny-all). app_rw (BYPASSRLS) is the only
-- accessor, matching how the tenant-scoped tables carry RLS.
ALTER TABLE app.budget_reservations ENABLE ROW LEVEL SECURITY;
