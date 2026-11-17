-- Additive usage acceptance order traceability: pre-existing subscriptions
-- require reconciliation for unversioned usage history, while newly accepted
-- usage inbox records bind a positive, per-subscription unique version.
ALTER TABLE billing_subscription
    ADD COLUMN usage_traceability_requires_reconciliation BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE billing_subscription
    ALTER COLUMN usage_traceability_requires_reconciliation SET DEFAULT false;

ALTER TABLE subscription_usage_inbox
    ADD COLUMN accepted_subscription_version BIGINT
    CONSTRAINT subscription_usage_acceptance_positive CHECK (
        accepted_subscription_version IS NULL OR accepted_subscription_version > 0
    );

CREATE UNIQUE INDEX subscription_usage_accepted_version_once
    ON subscription_usage_inbox (tenant_id, subscription_id, accepted_subscription_version)
    WHERE accepted_subscription_version IS NOT NULL;
