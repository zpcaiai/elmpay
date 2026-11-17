package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class DatabaseMigratorTest {
    @Test
    void usageWatermarkMigrationPreservesLegacyAndRejectsHalfNullOrMutableSeals() throws Exception {
        String url = LoopbackPostgresTestCluster.jdbcUrl();
        assertTrue(url != null && url.matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]+/elmpay_p1_[a-z0-9_]+"));
        assertEquals("elmpay_p1_admin",LoopbackPostgresTestCluster.adminUser());
        String suffix = UUID.randomUUID().toString().replace("-","");
        String schema = "p1_usage_schema_" + suffix;
        String owner = "p1_usage_owner_" + suffix;
        String tenant = UUID.randomUUID().toString();
        String project = UUID.randomUUID().toString();
        String plan = UUID.randomUUID().toString();
        String mandate = UUID.randomUUID().toString();
        String subscription = UUID.randomUUID().toString();
        String cycle = UUID.randomUUID().toString();
        try (Connection connection = DriverManager.getConnection(url,"elmpay_p1_admin","");
                Statement sql = connection.createStatement()) {
            sql.execute("CREATE ROLE " + owner + " NOLOGIN NOSUPERUSER NOBYPASSRLS");
            sql.execute("CREATE SCHEMA " + schema + " AUTHORIZATION " + owner);
            sql.execute("SET ROLE " + owner);
            sql.execute("SET search_path TO " + schema + ",public");
            sql.execute("SELECT set_config('app.tenant_id','" + tenant + "',false)");
            for (String name : new String[] {"V032__payment_runtime.sql","V034__durable_refund_runtime.sql",
                    "V012__event_delivery_runtime.sql","V012_1__event_envelope_revision.sql",
                    "V066__durable_commerce_runtime.sql"}) {
                for (String command : SqlScripts.split(resource("db/migration/" + name))) {
                    sql.execute(command);
                }
            }
            sql.execute("""
                    INSERT INTO billing_plan
                    (id,tenant_id,project_id,code,amount_minor,currency,billing_period_seconds,
                     trial_period_seconds,metered,created_at)
                    VALUES ('%s','%s','%s','legacy',100,'USD',60,0,true,now());
                    INSERT INTO billing_mandate
                    (id,tenant_id,project_id,customer_reference,provider,provider_mandate_reference,
                     payment_method_reference,purpose,maximum_amount_minor,currency,consent_digest,state,consented_at)
                    VALUES ('%s','%s','%s','test-customer','stripe','test-mandate','psp://stripe/test',
                     'renewal',10000,'USD',repeat('d',64),'active',now());
                    INSERT INTO billing_subscription
                    (id,tenant_id,project_id,customer_reference,plan_id,mandate_id,state,period_start,
                     period_end,usage_quantity,created_at,updated_at)
                    VALUES ('%s','%s','%s','test-customer','%s','%s','active',now()-interval '1 minute',now(),7,now(),now());
                    INSERT INTO subscription_billing_cycle
                    (id,tenant_id,project_id,subscription_id,period_start,period_end,amount_minor,currency,
                     state,created_at,updated_at)
                    VALUES ('%s','%s','%s','%s',now()-interval '1 minute',now(),500,'USD','queued',now(),now());
                    """.formatted(plan,tenant,project,mandate,tenant,project,subscription,tenant,project,
                            plan,mandate,cycle,tenant,project,subscription));
            for (String command : SqlScripts.split(resource("db/migration/V109__billing_usage_watermarks.sql"))) {
                sql.execute(command);
            }
            assertEquals("NULL:NULL:true:500",scalar(sql,"SELECT coalesce(captured_usage_quantity::text,'NULL')||':'||"
                    + "coalesce(usage_watermark_version::text,'NULL')||':'||usage_reconciliation_required||':'||amount_minor "
                    + "FROM subscription_billing_cycle"));
            assertEquals("7",scalar(sql,"SELECT usage_quantity::text FROM billing_subscription"));
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_billing_cycle SET captured_usage_quantity=5"));
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_billing_cycle SET usage_watermark_version=1"));
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_billing_cycle SET usage_reconciliation_required=false"));
            for (String invalid : new String[] {
                    "UPDATE subscription_billing_cycle SET captured_usage_quantity=-1,usage_watermark_version=1",
                    "UPDATE subscription_billing_cycle SET captured_usage_quantity=5,usage_watermark_version=0"}) {
                SQLException boundary = assertThrows(SQLException.class, () -> sql.execute(invalid));
                assertEquals("23514",boundary.getSQLState());
                assertTrue(boundary.getMessage().contains("billing_cycle_usage_seal_pair"));
            }
            sql.execute("UPDATE subscription_billing_cycle SET captured_usage_quantity=5,usage_watermark_version=1,usage_reconciliation_required=false");
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_billing_cycle SET captured_usage_quantity=-1"));
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_billing_cycle SET usage_watermark_version=0"));
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_billing_cycle SET captured_usage_quantity=6"));
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_billing_cycle SET amount_minor=600"));
            sql.execute("UPDATE subscription_billing_cycle SET state='succeeded',provider_result_digest=repeat('a',64)");
            assertEquals("5:1:false:succeeded",scalar(sql,"SELECT captured_usage_quantity||':'||usage_watermark_version||':'||"
                    + "usage_reconciliation_required||':'||state FROM subscription_billing_cycle"));
            sql.execute("INSERT INTO subscription_usage_inbox "
                    + "(tenant_id,project_id,subscription_id,idempotency_key,request_digest,quantity,received_at) "
                    + "VALUES ('" + tenant + "','" + project + "','" + subscription + "','legacy_usage',repeat('d',64),7,now())");
            for (String command : SqlScripts.split(resource("db/migration/V109_1__usage_acceptance_order.sql"))) {
                sql.execute(command);
            }
            assertEquals("true",scalar(sql,"SELECT usage_traceability_requires_reconciliation::text FROM billing_subscription"));
            assertEquals("1",scalar(sql,"SELECT count(*) FROM subscription_usage_inbox WHERE accepted_subscription_version IS NULL"));
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_usage_inbox SET accepted_subscription_version=1"));
            String acceptance = "INSERT INTO subscription_usage_inbox "
                    + "(tenant_id,project_id,subscription_id,idempotency_key,request_digest,quantity,received_at,accepted_subscription_version) "
                    + "VALUES ('" + tenant + "','" + project + "','" + subscription + "',?,repeat('a',64),2,now(),?)";
            try (var insert = connection.prepareStatement(acceptance)) {
                insert.setString(1,"invalid_version");insert.setLong(2,0);
                SQLException invalid = assertThrows(SQLException.class,insert::executeUpdate);
                assertEquals("23514",invalid.getSQLState());
                assertTrue(invalid.getMessage().contains("subscription_usage_acceptance_positive"));
                insert.setString(1,"ordered_usage");insert.setLong(2,2);assertEquals(1,insert.executeUpdate());
                insert.setString(1,"duplicate_version");
                SQLException duplicate = assertThrows(SQLException.class,insert::executeUpdate);
                assertEquals("23505",duplicate.getSQLState());
                assertTrue(duplicate.getMessage().contains("subscription_usage_accepted_version_once"));
            }
            assertEquals("1",scalar(sql,"SELECT count(*) FROM subscription_usage_inbox WHERE accepted_subscription_version=2"));
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_usage_inbox SET accepted_subscription_version=3 WHERE idempotency_key='ordered_usage'"));
            assertThrows(SQLException.class, () -> sql.execute("UPDATE subscription_usage_inbox SET quantity=3 WHERE idempotency_key='ordered_usage'"));
            assertThrows(SQLException.class, () -> sql.execute("DELETE FROM subscription_usage_inbox WHERE idempotency_key='ordered_usage'"));
            String postImage = scalar(sql,"SELECT row_to_json(c)::text FROM subscription_billing_cycle c")
                    + "|" + scalar(sql,"SELECT row_to_json(s)::text FROM billing_subscription s")
                    + "|" + scalar(sql,"SELECT string_agg(row_to_json(u)::text,',' ORDER BY idempotency_key) FROM subscription_usage_inbox u");
            String digest = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(postImage.getBytes(StandardCharsets.UTF_8)));
            sql.execute("SELECT set_config('app.tenant_id','" + UUID.randomUUID() + "',false)");
            assertEquals("0",scalar(sql,"SELECT count(*) FROM subscription_billing_cycle"));
            assertEquals("false",scalar(sql,"SELECT (rolsuper OR rolbypassrls)::text FROM pg_roles WHERE rolname=current_user"));
            System.out.println("usage_schema_jvm_pid=" + ProcessHandle.current().pid()
                    + " pg_backend_pid=" + scalar(sql,"SELECT pg_backend_pid()::text") + " schema=" + schema
                    + " db_postimage_sha256=" + digest);
        }
    }

    @Test
    void recoverySchemaUpgradesLegacyRowsOnRealPostgres() throws Exception {
        String url = LoopbackPostgresTestCluster.jdbcUrl();
        assertTrue(url != null && url.matches(
                "jdbc:postgresql://127\\.0\\.0\\.1:[0-9]+/elmpay_p1_[a-z0-9_]+"),
                "a dedicated loopback task PostgreSQL database is mandatory");
        assertEquals("elmpay_p1_admin", LoopbackPostgresTestCluster.adminUser());
        String suffix = UUID.randomUUID().toString().replace("-", "");
        String schema = "p1_webhook_" + suffix;
        String worker = "p1_webhook_worker_" + suffix;
        String owner = "p1_webhook_owner_" + suffix;
        try (Connection connection = DriverManager.getConnection(url, "elmpay_p1_admin", "");
                Statement sql = connection.createStatement()) {
            sql.execute("CREATE ROLE " + owner + " NOLOGIN NOSUPERUSER NOBYPASSRLS");
            sql.execute("CREATE SCHEMA " + schema + " AUTHORIZATION " + owner);
            sql.execute("SET ROLE " + owner);
            sql.execute("SET search_path TO " + schema + ",public");
            sql.execute("SELECT set_config('app.tenant_id','tenant_one',false)");
            for (String command : SqlScripts.split(resource("db/migration/V038__business_webhook_delivery.sql"))) {
                sql.execute(command);
            }
            sql.execute("""
                    INSERT INTO webhook_endpoint VALUES
                    ('tenant_one','project_one','endpoint_one','https://example.com/hook',
                     'example.com','ACTIVE',2,now(),now());
                    INSERT INTO webhook_delivery_outbox
                    (delivery_id,tenant_id,project_id,endpoint_id,event_id,event_type,payload,state,
                     attempt_count,next_attempt_at,created_at,updated_at)
                    OVERRIDING SYSTEM VALUE VALUES
                    (1,'tenant_one','project_one','endpoint_one','event_one','payment.succeeded',
                     decode('010203','hex'),'PENDING',0,now(),now(),now()),
                    (2,'tenant_one','project_one','endpoint_one','event_two','payment.succeeded',
                     decode('040506','hex'),'DEAD',2,now(),now(),now());
                    INSERT INTO webhook_delivery_dead_letter
                    (delivery_id,tenant_id,project_id,endpoint_id,event_id,event_type,payload,attempt_count,
                     final_status_code,final_error_code,failed_at,replayed_at,replayed_by,replay_ticket_id)
                    VALUES
                    (1,'tenant_one','project_one','endpoint_one','event_one','payment.succeeded',
                     decode('010203','hex'),2,503,'legacy_error',now()-interval '1 day',now(),'actor_one','ticket_one'),
                    (2,'tenant_one','project_one','endpoint_one','event_two','payment.succeeded',
                     decode('040506','hex'),2,504,'legacy_timeout',now()-interval '1 day',NULL,NULL,NULL);
                    """);
            String before = scalar(sql, "SELECT string_agg(row_to_json(d)::text, ',' ORDER BY delivery_id) "
                    + "FROM webhook_delivery_dead_letter d");
            sql.execute("SELECT set_config('app.tenant_id','',false)");
            for (String command : SqlScripts.split(resource("db/migration/V108__webhook_recovery_rounds.sql"))) {
                sql.execute(command);
            }
            sql.execute("SELECT set_config('app.tenant_id','tenant_one',false)");
            String after = scalar(sql, "SELECT string_agg((to_jsonb(d)-'recovery_round')::text, ',' "
                    + "ORDER BY delivery_id) FROM webhook_delivery_dead_letter d");
            // Compare canonical JSONB representations so only the additive round field is ignored.
            try (var query = connection.prepareStatement("SELECT ?::jsonb = ?::jsonb")) {
                query.setString(1, "[" + before + "]");
                query.setString(2, "[" + after + "]");
                try (ResultSet rows = query.executeQuery()) {
                    assertTrue(rows.next());
                    assertTrue(rows.getBoolean(1), "legacy payload/error/replay history must remain exact");
                }
            }
            assertEquals("2,1", scalar(sql, "SELECT string_agg(recovery_round::text,',' ORDER BY delivery_id) "
                    + "FROM webhook_delivery_outbox"));
            assertEquals("1,1", scalar(sql, "SELECT string_agg(recovery_round::text,',' ORDER BY delivery_id) "
                    + "FROM webhook_delivery_dead_letter"));
            sql.execute("INSERT INTO webhook_delivery_dead_letter SELECT delivery_id,tenant_id,project_id,"
                    + "endpoint_id,event_id,event_type,payload,2,502,'round_two',now(),NULL,NULL,NULL,2 "
                    + "FROM webhook_delivery_outbox WHERE delivery_id=1");
            assertThrows(SQLException.class, () -> sql.execute(
                    "INSERT INTO webhook_delivery_dead_letter SELECT delivery_id,tenant_id,project_id,"
                    + "endpoint_id,event_id,event_type,payload,2,502,'round_three',now(),NULL,NULL,NULL,3 "
                    + "FROM webhook_delivery_outbox WHERE delivery_id=1"));
            assertThrows(SQLException.class, () -> sql.execute(
                    "UPDATE webhook_delivery_dead_letter SET final_error_code='changed' WHERE recovery_round=1"));
            assertThrows(SQLException.class, () -> sql.execute(
                    "DELETE FROM webhook_delivery_dead_letter WHERE delivery_id=2"));
            assertThrows(SQLException.class, () -> sql.execute(
                    "UPDATE webhook_delivery_dead_letter SET replayed_by='actor_two' WHERE delivery_id=1 AND recovery_round=1"));
            sql.execute("UPDATE webhook_delivery_dead_letter SET replayed_at=now(),replayed_by='actor_two',"
                    + "replay_ticket_id='ticket_two' WHERE delivery_id=1 AND recovery_round=2");
            sql.execute("INSERT INTO webhook_delivery_admin_audit "
                    + "(tenant_id,action,target_id,actor_id,approver_id,reason,ticket_id,occurred_at) "
                    + "VALUES ('tenant_one','DEAD_LETTER_REPLAY','1','actor_one','approver_one','reason','ticket_one',now())");
            assertThrows(SQLException.class, () -> sql.execute("INSERT INTO webhook_delivery_admin_audit "
                    + "(tenant_id,action,target_id,actor_id,approver_id,reason,ticket_id,occurred_at) "
                    + "VALUES ('tenant_one','DEAD_LETTER_REPLAY','1','actor_one','approver_one','reason','ticket_one',now())"));
            assertThrows(SQLException.class, () -> sql.execute(
                    "UPDATE webhook_delivery_admin_audit SET reason='changed'"));
            assertThrows(SQLException.class, () -> sql.execute("DELETE FROM webhook_delivery_admin_audit"));
            sql.execute("RESET ROLE");
            sql.execute("CREATE ROLE " + worker + " NOLOGIN NOSUPERUSER NOBYPASSRLS");
            sql.execute("GRANT USAGE ON SCHEMA " + schema + " TO " + worker);
            sql.execute("GRANT SELECT,UPDATE ON webhook_delivery_outbox TO " + worker);
            sql.execute("GRANT INSERT ON webhook_delivery_dead_letter TO " + worker);
            sql.execute("SET ROLE " + worker);
            sql.execute("SELECT set_config('app.tenant_id','tenant_one',false)");
            assertEquals("false", scalar(sql, "SELECT (rolsuper OR rolbypassrls)::text FROM pg_roles WHERE rolname=current_user"));
            sql.execute("UPDATE webhook_delivery_outbox SET recovery_round=3 WHERE delivery_id=1");
            sql.execute("INSERT INTO webhook_delivery_dead_letter "
                    + "(delivery_id,tenant_id,project_id,endpoint_id,event_id,event_type,payload,attempt_count,"
                    + "final_status_code,final_error_code,failed_at,recovery_round) "
                    + "SELECT delivery_id,tenant_id,project_id,endpoint_id,event_id,event_type,payload,2,"
                    + "503,'round_three',now(),recovery_round FROM webhook_delivery_outbox WHERE delivery_id=1");
            assertThrows(SQLException.class, () -> sql.executeQuery("SELECT * FROM webhook_delivery_dead_letter"));
            sql.execute("SELECT set_config('app.tenant_id','tenant_two',false)");
            assertEquals("0", scalar(sql, "SELECT count(*) FROM webhook_delivery_outbox"));
            assertEquals(0, sql.executeUpdate("INSERT INTO webhook_delivery_dead_letter "
                    + "(delivery_id,tenant_id,project_id,endpoint_id,event_id,event_type,payload,attempt_count,"
                    + "final_status_code,final_error_code,failed_at,recovery_round) "
                    + "SELECT delivery_id,tenant_id,project_id,endpoint_id,event_id,event_type,payload,2,"
                    + "503,'wrong_tenant',now(),4 FROM webhook_delivery_outbox WHERE delivery_id=1"));
            sql.execute("RESET ROLE");
            String postImage = scalar(sql, "SELECT string_agg(to_jsonb(d)::text,',' ORDER BY delivery_id,recovery_round) "
                    + "FROM webhook_delivery_dead_letter d");
            String digest = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(postImage.getBytes(StandardCharsets.UTF_8)));
            String backendPid = scalar(sql, "SELECT pg_backend_pid()::text");
            System.out.println("webhook_schema_jvm_pid=" + ProcessHandle.current().pid()
                    + " pg_backend_pid=" + backendPid + " schema=" + schema
                    + " history_rows=4 postimage_sha256=" + digest);
        }
    }

    private static String scalar(Statement sql, String query) throws SQLException {
        try (ResultSet rows = sql.executeQuery(query)) {
            assertTrue(rows.next());
            return rows.getString(1);
        }
    }

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
                "db/migration/V107__runtime_role_acl_manifest.sql",
                "db/migration/V108__webhook_recovery_rounds.sql",
                "db/migration/V109__billing_usage_watermarks.sql",
                "db/migration/V109_1__usage_acceptance_order.sql"), resources);
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
