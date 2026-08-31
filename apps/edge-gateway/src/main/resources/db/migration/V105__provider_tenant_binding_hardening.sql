-- Additive tenant/project binding for provider, routing, checkout, and payment facts.
-- No row is rewritten across a tenant boundary: validation fails closed on any legacy drift.

ALTER TABLE project DROP CONSTRAINT IF EXISTS project_tenant_identity_key;
ALTER TABLE project ADD CONSTRAINT project_tenant_identity_key UNIQUE (tenant_id, id);
ALTER TABLE merchant DROP CONSTRAINT IF EXISTS merchant_tenant_identity_key;
ALTER TABLE merchant ADD CONSTRAINT merchant_tenant_identity_key UNIQUE (tenant_id, id);
ALTER TABLE provider_account DROP CONSTRAINT IF EXISTS provider_account_tenant_identity_key;
ALTER TABLE provider_account
    ADD CONSTRAINT provider_account_tenant_identity_key UNIQUE (tenant_id, id);
ALTER TABLE provider_account DROP CONSTRAINT IF EXISTS provider_account_project_identity_key;
ALTER TABLE provider_account
    ADD CONSTRAINT provider_account_project_identity_key UNIQUE (tenant_id, project_id, id);
ALTER TABLE payment_intent DROP CONSTRAINT IF EXISTS payment_intent_project_identity_key;
ALTER TABLE payment_intent
    ADD CONSTRAINT payment_intent_project_identity_key UNIQUE (tenant_id, project_id, id);
ALTER TABLE payment_attempt
    DROP CONSTRAINT IF EXISTS payment_attempt_intent_identity_key;
ALTER TABLE payment_attempt ADD CONSTRAINT payment_attempt_intent_identity_key
    UNIQUE (tenant_id, payment_intent_id, id);
ALTER TABLE checkout_session DROP CONSTRAINT IF EXISTS checkout_session_project_identity_key;
ALTER TABLE checkout_session
    ADD CONSTRAINT checkout_session_project_identity_key UNIQUE (tenant_id, project_id, session_id);

ALTER TABLE provider_account DROP CONSTRAINT IF EXISTS provider_account_tenant_project_fk;
ALTER TABLE provider_account ADD CONSTRAINT provider_account_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id) REFERENCES project (tenant_id, id)
    NOT VALID;
ALTER TABLE provider_account DROP CONSTRAINT IF EXISTS provider_account_tenant_merchant_fk;
ALTER TABLE provider_account ADD CONSTRAINT provider_account_tenant_merchant_fk
    FOREIGN KEY (tenant_id, merchant_id) REFERENCES merchant (tenant_id, id)
    NOT VALID;
ALTER TABLE provider_capability
    DROP CONSTRAINT IF EXISTS provider_capability_tenant_account_fk;
ALTER TABLE provider_capability ADD CONSTRAINT provider_capability_tenant_account_fk
    FOREIGN KEY (tenant_id, provider_account_id)
    REFERENCES provider_account (tenant_id, id) NOT VALID;
ALTER TABLE routing_rule DROP CONSTRAINT IF EXISTS routing_rule_tenant_project_fk;
ALTER TABLE routing_rule ADD CONSTRAINT routing_rule_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id) REFERENCES project (tenant_id, id) NOT VALID;
ALTER TABLE routing_rule DROP CONSTRAINT IF EXISTS routing_rule_tenant_account_fk;
ALTER TABLE routing_rule ADD CONSTRAINT routing_rule_tenant_account_fk
    FOREIGN KEY (tenant_id, project_id, provider_account_id)
    REFERENCES provider_account (tenant_id, project_id, id) NOT VALID;

ALTER TABLE payment_intent DROP CONSTRAINT IF EXISTS payment_intent_tenant_project_fk;
ALTER TABLE payment_intent ADD CONSTRAINT payment_intent_tenant_project_fk
    FOREIGN KEY (tenant_id, project_id) REFERENCES project (tenant_id, id) NOT VALID;
ALTER TABLE payment_intent DROP CONSTRAINT IF EXISTS payment_intent_tenant_merchant_fk;
ALTER TABLE payment_intent ADD CONSTRAINT payment_intent_tenant_merchant_fk
    FOREIGN KEY (tenant_id, merchant_id) REFERENCES merchant (tenant_id, id) NOT VALID;
ALTER TABLE payment_attempt DROP CONSTRAINT IF EXISTS payment_attempt_tenant_intent_fk;
ALTER TABLE payment_attempt ADD CONSTRAINT payment_attempt_tenant_intent_fk
    FOREIGN KEY (tenant_id, payment_intent_id)
    REFERENCES payment_intent (tenant_id, id) NOT VALID;
ALTER TABLE payment_attempt DROP CONSTRAINT IF EXISTS payment_attempt_tenant_account_fk;
ALTER TABLE payment_attempt ADD CONSTRAINT payment_attempt_tenant_account_fk
    FOREIGN KEY (tenant_id, provider_account_id)
    REFERENCES provider_account (tenant_id, id) NOT VALID;
DO $elmpay$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM payment_attempt attempt
          LEFT JOIN payment_intent intent
            ON intent.tenant_id = attempt.tenant_id
           AND intent.id = attempt.payment_intent_id
          LEFT JOIN provider_account account
            ON account.tenant_id = attempt.tenant_id
           AND account.id = attempt.provider_account_id
         WHERE intent.id IS NULL OR account.id IS NULL
            OR account.project_id IS DISTINCT FROM intent.project_id
    ) THEN
        RAISE EXCEPTION 'legacy payment attempt crosses tenant/project/provider authority'
            USING ERRCODE = '23514';
    END IF;
END;
$elmpay$;
CREATE OR REPLACE FUNCTION elmpay_validate_payment_attempt_provider_project()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM payment_intent intent
        JOIN provider_account account
          ON account.tenant_id = intent.tenant_id
         AND account.project_id = intent.project_id
       WHERE intent.tenant_id = NEW.tenant_id AND intent.id = NEW.payment_intent_id
         AND account.id = NEW.provider_account_id
    ) THEN
        RAISE EXCEPTION 'payment attempt provider is outside intent tenant/project'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$elmpay$;
DROP TRIGGER IF EXISTS payment_attempt_provider_project_guard ON payment_attempt;
CREATE TRIGGER payment_attempt_provider_project_guard
BEFORE INSERT OR UPDATE OF tenant_id, payment_intent_id, provider_account_id
ON payment_attempt FOR EACH ROW
EXECUTE FUNCTION elmpay_validate_payment_attempt_provider_project();
REVOKE ALL ON FUNCTION elmpay_validate_payment_attempt_provider_project() FROM PUBLIC;

ALTER TABLE routing_policy_rule DROP CONSTRAINT IF EXISTS routing_policy_rule_tenant_account_fk;
ALTER TABLE routing_policy_rule ADD CONSTRAINT routing_policy_rule_tenant_account_fk
    FOREIGN KEY (tenant_id, project_id, provider_account_id)
    REFERENCES provider_account (tenant_id, project_id, id) NOT VALID;
ALTER TABLE routing_decision DROP CONSTRAINT IF EXISTS routing_decision_tenant_account_fk;
ALTER TABLE routing_decision ADD CONSTRAINT routing_decision_tenant_account_fk
    FOREIGN KEY (tenant_id, project_id, provider_account_id)
    REFERENCES provider_account (tenant_id, project_id, id) NOT VALID;

ALTER TABLE checkout_session DROP CONSTRAINT IF EXISTS checkout_session_project_intent_fk;
ALTER TABLE checkout_session ADD CONSTRAINT checkout_session_project_intent_fk
    FOREIGN KEY (tenant_id, project_id, payment_intent_id)
    REFERENCES payment_intent (tenant_id, project_id, id) NOT VALID;
ALTER TABLE checkout_session DROP CONSTRAINT IF EXISTS checkout_session_tenant_merchant_fk;
ALTER TABLE checkout_session ADD CONSTRAINT checkout_session_tenant_merchant_fk
    FOREIGN KEY (tenant_id, merchant_id) REFERENCES merchant (tenant_id, id) NOT VALID;
ALTER TABLE checkout_provider_sdk_audit
    DROP CONSTRAINT IF EXISTS checkout_provider_sdk_audit_session_fk;
ALTER TABLE checkout_provider_sdk_audit ADD CONSTRAINT checkout_provider_sdk_audit_session_fk
    FOREIGN KEY (tenant_id, project_id, checkout_session_id)
    REFERENCES checkout_session (tenant_id, project_id, session_id) NOT VALID;
ALTER TABLE checkout_provider_sdk_audit
    DROP CONSTRAINT IF EXISTS checkout_provider_sdk_audit_intent_fk;
ALTER TABLE checkout_provider_sdk_audit ADD CONSTRAINT checkout_provider_sdk_audit_intent_fk
    FOREIGN KEY (tenant_id, project_id, payment_intent_id)
    REFERENCES payment_intent (tenant_id, project_id, id) NOT VALID;
ALTER TABLE checkout_provider_sdk_audit
    DROP CONSTRAINT IF EXISTS checkout_provider_sdk_audit_account_fk;
ALTER TABLE checkout_provider_sdk_audit ADD CONSTRAINT checkout_provider_sdk_audit_account_fk
    FOREIGN KEY (tenant_id, project_id, provider_account_id)
    REFERENCES provider_account (tenant_id, project_id, id) NOT VALID;
ALTER TABLE checkout_provider_sdk_audit
    DROP CONSTRAINT IF EXISTS checkout_provider_sdk_audit_merchant_fk;
ALTER TABLE checkout_provider_sdk_audit ADD CONSTRAINT checkout_provider_sdk_audit_merchant_fk
    FOREIGN KEY (tenant_id, merchant_id) REFERENCES merchant (tenant_id, id) NOT VALID;

ALTER TABLE provider_effect_expectation
    DROP CONSTRAINT IF EXISTS provider_effect_expectation_intent_project_fk;
ALTER TABLE provider_effect_expectation ADD CONSTRAINT provider_effect_expectation_intent_project_fk
    FOREIGN KEY (tenant_id, project_id, payment_intent_id)
    REFERENCES payment_intent (tenant_id, project_id, id) NOT VALID;
ALTER TABLE provider_effect_expectation
    DROP CONSTRAINT IF EXISTS provider_effect_expectation_attempt_project_fk;
ALTER TABLE provider_effect_expectation ADD CONSTRAINT provider_effect_expectation_attempt_project_fk
    FOREIGN KEY (tenant_id, payment_intent_id, payment_attempt_id)
    REFERENCES payment_attempt (tenant_id, payment_intent_id, id) NOT VALID;
ALTER TABLE provider_effect_expectation
    DROP CONSTRAINT IF EXISTS provider_effect_expectation_account_project_fk;
ALTER TABLE provider_effect_expectation ADD CONSTRAINT provider_effect_expectation_account_project_fk
    FOREIGN KEY (tenant_id, project_id, provider_account_id)
    REFERENCES provider_account (tenant_id, project_id, id) NOT VALID;

ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_provider_account_project_fk;
DO $elmpay$
BEGIN
    IF EXISTS (SELECT 1 FROM refund WHERE project_id IS NULL) THEN
        RAISE EXCEPTION 'legacy refund lacks immutable project authority'
            USING ERRCODE = '23514';
    END IF;
END;
$elmpay$;
ALTER TABLE refund ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_payment_project_fk;
ALTER TABLE refund ADD CONSTRAINT refund_payment_project_fk
    FOREIGN KEY (tenant_id, project_id, payment_intent_id)
    REFERENCES payment_intent (tenant_id, project_id, id) NOT VALID;
ALTER TABLE refund ADD CONSTRAINT refund_provider_account_project_fk
    FOREIGN KEY (tenant_id, project_id, provider_account_id)
    REFERENCES provider_account (tenant_id, project_id, id) NOT VALID;
ALTER TABLE provider_call_circuit DROP CONSTRAINT IF EXISTS provider_call_circuit_account_fk;
ALTER TABLE provider_call_circuit ADD CONSTRAINT provider_call_circuit_account_fk
    FOREIGN KEY (tenant_id, provider_account_id)
    REFERENCES provider_account (tenant_id, id) NOT VALID;
ALTER TABLE provider_call_outcome DROP CONSTRAINT IF EXISTS provider_call_outcome_account_fk;
ALTER TABLE provider_call_outcome ADD CONSTRAINT provider_call_outcome_account_fk
    FOREIGN KEY (tenant_id, provider_account_id)
    REFERENCES provider_account (tenant_id, id) NOT VALID;
ALTER TABLE merchant_onboarding DROP CONSTRAINT IF EXISTS merchant_onboarding_account_project_fk;
ALTER TABLE merchant_onboarding ADD CONSTRAINT merchant_onboarding_account_project_fk
    FOREIGN KEY (tenant_id, project_id, provider_account_id)
    REFERENCES provider_account (tenant_id, project_id, id) NOT VALID;

ALTER TABLE provider_account VALIDATE CONSTRAINT provider_account_tenant_project_fk;
ALTER TABLE provider_account VALIDATE CONSTRAINT provider_account_tenant_merchant_fk;
ALTER TABLE provider_capability VALIDATE CONSTRAINT provider_capability_tenant_account_fk;
ALTER TABLE routing_rule VALIDATE CONSTRAINT routing_rule_tenant_project_fk;
ALTER TABLE routing_rule VALIDATE CONSTRAINT routing_rule_tenant_account_fk;
ALTER TABLE payment_intent VALIDATE CONSTRAINT payment_intent_tenant_project_fk;
ALTER TABLE payment_intent VALIDATE CONSTRAINT payment_intent_tenant_merchant_fk;
ALTER TABLE payment_attempt VALIDATE CONSTRAINT payment_attempt_tenant_intent_fk;
ALTER TABLE payment_attempt VALIDATE CONSTRAINT payment_attempt_tenant_account_fk;
ALTER TABLE routing_policy_rule VALIDATE CONSTRAINT routing_policy_rule_tenant_account_fk;
ALTER TABLE routing_decision VALIDATE CONSTRAINT routing_decision_tenant_account_fk;
ALTER TABLE checkout_session VALIDATE CONSTRAINT checkout_session_project_intent_fk;
ALTER TABLE checkout_session VALIDATE CONSTRAINT checkout_session_tenant_merchant_fk;
ALTER TABLE checkout_provider_sdk_audit VALIDATE CONSTRAINT checkout_provider_sdk_audit_session_fk;
ALTER TABLE checkout_provider_sdk_audit VALIDATE CONSTRAINT checkout_provider_sdk_audit_intent_fk;
ALTER TABLE checkout_provider_sdk_audit VALIDATE CONSTRAINT checkout_provider_sdk_audit_account_fk;
ALTER TABLE checkout_provider_sdk_audit VALIDATE CONSTRAINT checkout_provider_sdk_audit_merchant_fk;
ALTER TABLE provider_effect_expectation VALIDATE CONSTRAINT provider_effect_expectation_intent_project_fk;
ALTER TABLE provider_effect_expectation VALIDATE CONSTRAINT provider_effect_expectation_attempt_project_fk;
ALTER TABLE provider_effect_expectation VALIDATE CONSTRAINT provider_effect_expectation_account_project_fk;
ALTER TABLE refund VALIDATE CONSTRAINT refund_provider_account_project_fk;
ALTER TABLE refund VALIDATE CONSTRAINT refund_payment_project_fk;
ALTER TABLE provider_call_circuit VALIDATE CONSTRAINT provider_call_circuit_account_fk;
ALTER TABLE provider_call_outcome VALIDATE CONSTRAINT provider_call_outcome_account_fk;
ALTER TABLE merchant_onboarding VALIDATE CONSTRAINT merchant_onboarding_account_project_fk;

-- Existing single-column foreign keys are retained as redundant integrity checks. The composite
-- constraints above are the tenant/project authority proof used by runtime schema validation.
-- Rollback is manual: remove only after proving every referencing boundary is tenant-safe.
