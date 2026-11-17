-- Additive upgrade: each approved replay starts a new delivery round. Historical
-- failure payloads and approval receipts remain durable; the worker keeps its
-- INSERT-only access to dead letters and reads the round from its owned outbox.
ALTER TABLE webhook_delivery_outbox
    ADD COLUMN recovery_round BIGINT NOT NULL DEFAULT 1 CHECK (recovery_round > 0);
ALTER TABLE webhook_delivery_dead_letter
    ADD COLUMN recovery_round BIGINT NOT NULL DEFAULT 1 CHECK (recovery_round > 0);

-- The dedicated non-bypass owner performs this cross-tenant backfill inside
-- the migrator's transaction. FORCE RLS stays enabled; runtime identities never
-- receive this temporary owner-only policy.
CREATE POLICY webhook_recovery_owner_upgrade ON webhook_delivery_outbox
    TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY webhook_history_owner_upgrade ON webhook_delivery_dead_letter
    TO CURRENT_USER USING (true);
UPDATE webhook_delivery_outbox o SET recovery_round = 2
FROM webhook_delivery_dead_letter d
WHERE d.tenant_id = o.tenant_id AND d.delivery_id = o.delivery_id
  AND d.replayed_at IS NOT NULL;
DROP POLICY webhook_recovery_owner_upgrade ON webhook_delivery_outbox;
DROP POLICY webhook_history_owner_upgrade ON webhook_delivery_dead_letter;

ALTER TABLE webhook_delivery_dead_letter DROP CONSTRAINT webhook_delivery_dead_letter_pkey;
ALTER TABLE webhook_delivery_dead_letter
    ADD PRIMARY KEY (tenant_id, delivery_id, recovery_round),
    ADD CHECK ((replayed_at IS NULL AND replayed_by IS NULL AND replay_ticket_id IS NULL)
            OR (replayed_at IS NOT NULL AND replayed_by IS NOT NULL AND replay_ticket_id IS NOT NULL));
CREATE UNIQUE INDEX webhook_dead_letter_open_round
    ON webhook_delivery_dead_letter (tenant_id, delivery_id) WHERE replayed_at IS NULL;
CREATE UNIQUE INDEX webhook_replay_request_once
    ON webhook_delivery_admin_audit (tenant_id, target_id, ticket_id)
    WHERE action = 'DEAD_LETTER_REPLAY';

CREATE FUNCTION webhook_preserve_dead_letter_history() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'webhook failure history is immutable';
    END IF;
    IF OLD.replayed_at IS NOT NULL OR NEW.replayed_at IS NULL
       OR NEW.replayed_by IS NULL OR NEW.replay_ticket_id IS NULL
       OR (to_jsonb(NEW) - 'replayed_at' - 'replayed_by' - 'replay_ticket_id')
          IS DISTINCT FROM
          (to_jsonb(OLD) - 'replayed_at' - 'replayed_by' - 'replay_ticket_id') THEN
        RAISE EXCEPTION 'only the first approved replay may update failure history';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION webhook_preserve_dead_letter_history() FROM PUBLIC;
CREATE TRIGGER webhook_dead_letter_history_immutable
    BEFORE UPDATE OR DELETE ON webhook_delivery_dead_letter
    FOR EACH ROW EXECUTE FUNCTION webhook_preserve_dead_letter_history();

CREATE FUNCTION webhook_preserve_admin_audit() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'webhook approval audit is immutable';
END;
$$;
REVOKE ALL ON FUNCTION webhook_preserve_admin_audit() FROM PUBLIC;
CREATE TRIGGER webhook_admin_audit_immutable
    BEFORE UPDATE OR DELETE ON webhook_delivery_admin_audit
    FOR EACH ROW EXECUTE FUNCTION webhook_preserve_admin_audit();
