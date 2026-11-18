-- Additive usage acceptance order traceability: pre-existing subscriptions with
-- unversioned usage history require reconciliation, while newly accepted usage
-- inbox records bind a positive, per-subscription unique version.
ALTER TABLE billing_subscription
    ADD COLUMN usage_traceability_requires_reconciliation BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE subscription_usage_inbox
    ADD COLUMN accepted_subscription_version BIGINT
    CONSTRAINT subscription_usage_acceptance_positive CHECK (
        accepted_subscription_version IS NULL OR accepted_subscription_version > 0
    );

CREATE UNIQUE INDEX subscription_usage_accepted_version_once
    ON subscription_usage_inbox (tenant_id, subscription_id, accepted_subscription_version)
    WHERE accepted_subscription_version IS NOT NULL;

CREATE POLICY billing_subscription_usage_traceability_upgrade ON billing_subscription
    TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY subscription_usage_inbox_traceability_upgrade ON subscription_usage_inbox
    TO CURRENT_USER USING (true);
UPDATE billing_subscription s
   SET usage_traceability_requires_reconciliation = true
 WHERE s.usage_quantity > 0
    OR EXISTS (
        SELECT 1 FROM subscription_usage_inbox u
         WHERE u.tenant_id = s.tenant_id
           AND u.subscription_id = s.id
           AND u.accepted_subscription_version IS NULL
    );
DROP POLICY billing_subscription_usage_traceability_upgrade ON billing_subscription;
DROP POLICY subscription_usage_inbox_traceability_upgrade ON subscription_usage_inbox;

CREATE FUNCTION require_subscription_usage_acceptance_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.accepted_subscription_version IS NULL THEN
        RAISE EXCEPTION 'new subscription usage inbox rows require accepted_subscription_version'
            USING ERRCODE = '23502';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION require_subscription_usage_acceptance_version() FROM PUBLIC;
CREATE TRIGGER subscription_usage_acceptance_version_required
    BEFORE INSERT ON subscription_usage_inbox
    FOR EACH ROW EXECUTE FUNCTION require_subscription_usage_acceptance_version();

CREATE FUNCTION preserve_subscription_usage_traceability_flag() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.usage_traceability_requires_reconciliation
       AND NOT NEW.usage_traceability_requires_reconciliation THEN
        RAISE EXCEPTION 'usage traceability reconciliation requirement cannot be cleared in place';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION preserve_subscription_usage_traceability_flag() FROM PUBLIC;
CREATE TRIGGER billing_subscription_usage_traceability_immutable
    BEFORE UPDATE ON billing_subscription
    FOR EACH ROW EXECUTE FUNCTION preserve_subscription_usage_traceability_flag();
