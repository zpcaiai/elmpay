package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
                "db/migration/V023__audit_timestamp_anchor.sql",
                "db/migration/V024__tenant_project_registry.sql",
                "db/migration/V025__merchant_kyb_profile.sql",
                "db/migration/V028__versioned_routing_policy.sql",
                "db/migration/V030__merchant_onboarding_workflow.sql",
                "db/migration/V033__payment_action_receipts.sql",
                "db/migration/V034__durable_refund_runtime.sql",
                "db/migration/V035__payment_intent_metadata.sql",
                "db/migration/V036__payment_attempt_close.sql",
                "db/migration/V037__provider_webhook_inbox.sql",
                "db/migration/V038__business_webhook_delivery.sql",
                "db/migration/V039__payment_timeline_read_model.sql",
                "db/migration/V054__apple_pay_lifecycle.sql",
                "db/migration/V056__checkout_sessions.sql",
                "db/migration/V057__durable_payment_links.sql",
                "db/migration/V062__checkout_capability_health.sql",
                "db/migration/V066__durable_commerce_runtime.sql",
                "db/migration/V072__immutable_ledger.sql",
                "db/migration/V076__reconciliation.sql",
                "db/migration/V079__financial_runtime.sql",
                "db/migration/V100__provider_call_circuit.sql"), resources);
        for (String resource : resources) {
            assertNotNull(getClass().getClassLoader().getResource(resource), resource);
        }
    }
}
