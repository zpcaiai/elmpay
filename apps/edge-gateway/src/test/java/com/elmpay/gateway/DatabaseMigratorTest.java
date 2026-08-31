package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

final class DatabaseMigratorTest {
    @Test
    void everyProductionMigrationHasAUniquePackagedResource() {
        List<String> resources = DatabaseMigrator.migrationResources();
        assertEquals(resources.size(), resources.stream().distinct().count());
        assertEquals(List.of(
                "db/migration/V032__payment_runtime.sql",
                "db/migration/V012__event_delivery_runtime.sql",
                "db/migration/V012_1__event_envelope_revision.sql",
                "db/migration/V013__tenant_partition_archive.sql",
                "db/migration/V023__audit_timestamp_anchor.sql",
                "db/migration/V024__tenant_project_registry.sql",
                "db/migration/V025__merchant_kyb_profile.sql",
                "db/migration/V028__versioned_routing_policy.sql",
                "db/migration/V030__merchant_onboarding_workflow.sql",
                "db/migration/V101__tenant_authority_evidence.sql",
                "V018_019__admin_web_runtime.sql",
                "db/migration/V033__payment_action_receipts.sql",
                "db/migration/V034__durable_refund_runtime.sql",
                "db/migration/V035__payment_intent_metadata.sql",
                "db/migration/V036__payment_attempt_close.sql",
                "db/migration/V036_1__payment_attempt_leases.sql",
                "db/migration/V036_2__verified_provider_effect_runtime.sql",
                "db/migration/V037__provider_webhook_inbox.sql",
                "db/migration/V037_1__provider_webhook_processing.sql",
                "db/migration/V037_2__provider_webhook_processor_runtime.sql",
                "db/migration/V038__business_webhook_delivery.sql",
                "db/migration/V039__payment_timeline_read_model.sql",
                "db/migration/V054__apple_pay_lifecycle.sql",
                "db/migration/V056__checkout_sessions.sql",
                "db/migration/V056_1__checkout_provider_sdk_audit.sql",
                "db/migration/V057__durable_payment_links.sql",
                "db/migration/V062__checkout_capability_health.sql",
                "db/migration/V066__durable_commerce_runtime.sql",
                "db/migration/V066_1__provider_evidence_receipts.sql",
                "db/migration/V072__immutable_ledger.sql",
                "db/migration/V073__event_ledger_posting_policy.sql",
                "db/migration/V076__reconciliation.sql",
                "db/migration/V079__financial_runtime.sql",
                "db/migration/V079_1__reconciliation_snapshot_scheduler.sql",
                "db/migration/V080_087__risk_control.sql",
                "db/migration/V087_1__admin_action_effects.sql",
                "db/migration/V102__risk_engine_runtime.sql",
                "db/migration/V087_2__admin_rollout_effects.sql",
                "db/migration/V103__admin_queue_runtime_role_hardening.sql",
                "db/migration/V104__reconciliation_scheduler_hardening.sql",
                "db/migration/V100__provider_call_circuit.sql",
                "db/migration/V105__provider_tenant_binding_hardening.sql",
                "db/migration/V106__tenant_partition_maintenance_hardening.sql",
                "db/migration/V107__runtime_role_acl_manifest.sql"), resources);
        for (String resource : resources) {
            assertNotNull(getClass().getClassLoader().getResource(resource), resource);
        }
    }

    @Test
    void appleAndRiskMigrationsForceFailClosedTenantIsolation() throws IOException {
        String apple = resource("db/migration/V054__apple_pay_lifecycle.sql");
        assertEquals(3, count(apple, "ENABLE ROW LEVEL SECURITY"));
        assertEquals(3, count(apple, "FORCE ROW LEVEL SECURITY"));
        assertEquals(6, count(apple, "current_setting('app.tenant_id', true)"));

        String risk = resource("db/migration/V080_087__risk_control.sql");
        assertEquals(8, count(risk, "ENABLE ROW LEVEL SECURITY"));
        assertEquals(8, count(risk, "FORCE ROW LEVEL SECURITY"));
        assertEquals(16, count(risk, "current_setting('app.tenant_id', true)"));
        assertFalse(risk.contains("elmpay.tenant_id"));
        assertTrue(risk.contains("CREATE POLICY risk_audit_tenant"));

        String checkoutSdk = resource(
                "db/migration/V056_1__checkout_provider_sdk_audit.sql");
        assertEquals(1, count(checkoutSdk, "ENABLE ROW LEVEL SECURITY"));
        assertEquals(1, count(checkoutSdk, "FORCE ROW LEVEL SECURITY"));
        assertTrue(checkoutSdk.contains("BEFORE UPDATE OR DELETE"));
        assertTrue(checkoutSdk.contains("channel_digest"));
        assertTrue(checkoutSdk.contains("checkout_snapshot_digest"));

        String adminAction = resource("db/migration/V087_1__admin_action_effects.sql");
        assertTrue(adminAction.contains("admin_action_effect_receipt_immutable"));
        assertTrue(adminAction.contains("admin_domain_command_signal"));
        assertTrue(adminAction.contains("project_id uuid NOT NULL"));

        String adminHardening = resource(
                "db/migration/V103__admin_queue_runtime_role_hardening.sql");
        assertTrue(adminHardening.contains(
                "ALTER TABLE admin_domain_command_signal FORCE ROW LEVEL SECURITY"));
        assertTrue(adminHardening.contains("elmpay.admin-command-db-api.v1"));
        assertTrue(adminHardening.contains("session_user = 'elmpay_risk_engine'"));
        assertTrue(adminHardening.contains("FROM elmpay_edge_gateway, elmpay_risk_engine,"
                + " elmpay_worker"));
        assertTrue(adminHardening.contains("elmpay_apply_admin_rollout_approval"));
        assertTrue(adminHardening.contains(
                "v_command.source_dispatch_fencing_token <>"));
        assertFalse(adminHardening.contains("current_setting('elmpay.tenant_id'"));

        String rolloutAction = resource("db/migration/V087_2__admin_rollout_effects.sql");
        assertEquals(2, count(rolloutAction, "ENABLE ROW LEVEL SECURITY"));
        assertEquals(2, count(rolloutAction, "FORCE ROW LEVEL SECURITY"));
        assertTrue(rolloutAction.contains("admin_rollout_stage_approval"));
        assertTrue(rolloutAction.contains("stage_proposal_digest"));

        String archive = resource("db/migration/V013__tenant_partition_archive.sql");
        assertTrue(archive.contains("tenant_archive_export_receipt"));
        assertTrue(archive.contains("tenant_partition_change"));

        String providerBinding = resource(
                "db/migration/V105__provider_tenant_binding_hardening.sql");
        assertTrue(providerBinding.contains("provider_capability_tenant_account_fk"));
        assertTrue(providerBinding.contains("routing_policy_rule_tenant_account_fk"));
        assertTrue(providerBinding.contains("payment_attempt_provider_project_guard"));
        assertTrue(providerBinding.contains("legacy payment attempt crosses"));
        assertTrue(providerBinding.contains("payment_attempt_intent_identity_key"));
        assertTrue(providerBinding.contains(
                "FOREIGN KEY (tenant_id, payment_intent_id, payment_attempt_id)"));
        assertTrue(providerBinding.contains("refund_payment_project_fk"));
        assertTrue(providerBinding.contains("VALIDATE CONSTRAINT"));

        String partitionHardening = resource(
                "db/migration/V106__tenant_partition_maintenance_hardening.sql");
        assertTrue(partitionHardening.contains("elmpay_ensure_archive_partitions"));
        assertTrue(partitionHardening.contains(
                "independent-ed25519-all-tenant-release"));
        assertTrue(partitionHardening.contains("elmpay_detach_archive_partition"));
        assertTrue(partitionHardening.contains("tenant_archive_verifier_nonce"));
        assertTrue(partitionHardening.contains("actor_verifier_key_id"));
        assertTrue(partitionHardening.contains("approver_verifier_key_id"));
        assertTrue(partitionHardening.contains(
                "p_actor_verifier_key_id = p_approver_verifier_key_id"));
        assertTrue(partitionHardening.contains(
                "v_authorization.partition_release_key_id IS DISTINCT FROM"));
        assertTrue(partitionHardening.contains("object_uri !~ '[?#@%]'"));
        assertTrue(partitionHardening.contains(
                "legacy archive receipt ingestion is disabled"));

        String runtimeAcl = resource("db/migration/V107__runtime_role_acl_manifest.sql");
        assertTrue(runtimeAcl.contains("runtime role % is absent or over-privileged"));
        assertTrue(runtimeAcl.contains("REVOKE CREATE, TEMPORARY ON DATABASE %I"));
        assertTrue(runtimeAcl.contains("REVOKE ALL PRIVILEGES ON SCHEMA %I"));
        assertTrue(runtimeAcl.contains("REVOKE ALL PRIVILEGES (%s) ON TABLE"));
        assertTrue(runtimeAcl.contains("GRANT EXECUTE ON FUNCTION"));
        assertFalse(runtimeAcl.contains("ON DATABASE elmpay"));
    }

    private static String resource(String name) throws IOException {
        try (var stream = DatabaseMigratorTest.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(stream, name);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static int count(String value, String needle) {
        return (value.length() - value.replace(needle, "").length()) / needle.length();
    }

}
