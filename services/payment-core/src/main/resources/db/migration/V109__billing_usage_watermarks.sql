-- Do not infer historical quantities from today's plan or amount. Old rows are
-- explicitly unsealed and require reconciliation; new code writes both fields
-- and clears this marker in the atomic snapshot transaction.
ALTER TABLE subscription_billing_cycle
    ADD COLUMN captured_usage_quantity BIGINT,
    ADD COLUMN usage_watermark_version BIGINT,
    ADD COLUMN usage_reconciliation_required BOOLEAN NOT NULL DEFAULT true,
    ADD CONSTRAINT billing_cycle_usage_seal_pair CHECK (
        (captured_usage_quantity IS NULL AND usage_watermark_version IS NULL
            AND usage_reconciliation_required)
        OR (captured_usage_quantity IS NOT NULL AND usage_watermark_version IS NOT NULL
            AND captured_usage_quantity >= 0 AND usage_watermark_version > 0)
    );

CREATE FUNCTION preserve_billing_usage_seal() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.captured_usage_quantity IS NOT NULL AND
       ROW(NEW.id,NEW.tenant_id,NEW.project_id,NEW.subscription_id,
           NEW.period_start,NEW.period_end,NEW.amount_minor,NEW.currency,
           NEW.captured_usage_quantity,NEW.usage_watermark_version,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.tenant_id,OLD.project_id,OLD.subscription_id,
           OLD.period_start,OLD.period_end,OLD.amount_minor,OLD.currency,
           OLD.captured_usage_quantity,OLD.usage_watermark_version,OLD.created_at) THEN
        RAISE EXCEPTION 'sealed billing quantity and price facts are immutable';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION preserve_billing_usage_seal() FROM PUBLIC;
CREATE TRIGGER billing_usage_seal_immutable
    BEFORE UPDATE ON subscription_billing_cycle
    FOR EACH ROW EXECUTE FUNCTION preserve_billing_usage_seal();
