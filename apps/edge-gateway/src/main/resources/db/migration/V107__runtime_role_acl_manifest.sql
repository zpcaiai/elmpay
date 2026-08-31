-- Additive exact runtime-role ACL manifest. Runtime identities own no database objects and have
-- no implicit PUBLIC routine/table/sequence capability. Every grant below is backed by a
-- production JDBC path and is checked again by the corresponding startup schema verifier.

DO $elmpay$
DECLARE required_role text;
DECLARE provisioned_count integer;
BEGIN
  FOREACH required_role IN ARRAY ARRAY[
    'elmpay_edge_gateway','elmpay_worker','elmpay_risk_engine',
    'elmpay_webhook_processor','elmpay_admin_web','elmpay_partition_precreator',
    'elmpay_archive_verifier','elmpay_partition_detacher'
  ] LOOP
    SELECT count(*) INTO provisioned_count
      FROM pg_roles role
     WHERE role.rolname = required_role
       AND role.rolcanlogin
       AND NOT role.rolinherit
       AND NOT role.rolsuper
       AND NOT role.rolbypassrls
       AND NOT role.rolcreaterole
       AND NOT role.rolcreatedb
       AND NOT role.rolreplication
       AND role.rolconfig IS NULL
       AND NOT EXISTS (
         SELECT 1 FROM pg_auth_members membership
          WHERE membership.member = role.oid);
    IF provisioned_count <> 1 THEN
      RAISE EXCEPTION 'runtime role % is absent or over-privileged before V107', required_role
        USING ERRCODE = '42501';
    END IF;
  END LOOP;
END;
$elmpay$;

DO $elmpay$
BEGIN
  EXECUTE format(
    'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC, elmpay_edge_gateway, elmpay_worker, '
    || 'elmpay_risk_engine, elmpay_webhook_processor, elmpay_admin_web, '
    || 'elmpay_partition_precreator, elmpay_archive_verifier, elmpay_partition_detacher',
    current_database());
  EXECUTE format(
    'GRANT CONNECT ON DATABASE %I TO elmpay_edge_gateway, elmpay_worker, '
    || 'elmpay_risk_engine, elmpay_webhook_processor, elmpay_admin_web, '
    || 'elmpay_partition_precreator, elmpay_archive_verifier, elmpay_partition_detacher',
    current_database());
END;
$elmpay$;

DO $elmpay$
DECLARE application_schema record;
BEGIN
  FOR application_schema IN
    SELECT namespace.nspname
      FROM pg_namespace namespace
     WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
       AND namespace.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON SCHEMA %I FROM PUBLIC, elmpay_edge_gateway, '
      || 'elmpay_worker, elmpay_risk_engine, elmpay_webhook_processor, '
      || 'elmpay_admin_web, elmpay_partition_precreator, elmpay_archive_verifier, '
      || 'elmpay_partition_detacher', application_schema.nspname);
  END LOOP;
END;
$elmpay$;

GRANT USAGE ON SCHEMA public TO elmpay_edge_gateway, elmpay_worker,
  elmpay_risk_engine, elmpay_webhook_processor, elmpay_admin_web,
  elmpay_partition_precreator, elmpay_archive_verifier, elmpay_partition_detacher;

DO $elmpay$
DECLARE item record;
DECLARE runtime_role text;
BEGIN
  FOR item IN
    SELECT n.nspname, c.relname, c.relkind,
           (SELECT string_agg(format('%I', attribute.attname), ',')
              FROM pg_attribute attribute
             WHERE attribute.attrelid = c.oid
               AND attribute.attnum > 0 AND NOT attribute.attisdropped) AS columns
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname NOT IN ('pg_catalog','information_schema')
       AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
       AND c.relkind IN ('r','p','f','v','m','S')
  LOOP
    EXECUTE format('REVOKE ALL PRIVILEGES ON %s %I.%I FROM PUBLIC',
      CASE WHEN item.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
      item.nspname, item.relname);
    IF item.relkind <> 'S' AND item.columns IS NOT NULL THEN
      EXECUTE format('REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM PUBLIC',
        item.columns, item.nspname, item.relname);
    END IF;
    FOREACH runtime_role IN ARRAY ARRAY[
      'elmpay_edge_gateway','elmpay_worker','elmpay_risk_engine',
      'elmpay_webhook_processor','elmpay_admin_web','elmpay_partition_precreator',
      'elmpay_archive_verifier','elmpay_partition_detacher'
    ] LOOP
      EXECUTE format('REVOKE ALL PRIVILEGES ON %s %I.%I FROM %I',
        CASE WHEN item.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
        item.nspname, item.relname, runtime_role);
      IF item.relkind <> 'S' AND item.columns IS NOT NULL THEN
        EXECUTE format('REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM %I',
          item.columns, item.nspname, item.relname, runtime_role);
      END IF;
    END LOOP;
  END LOOP;
  FOR item IN
    SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) AS arguments,
           p.prokind
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname NOT IN ('pg_catalog','information_schema')
       AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  LOOP
    EXECUTE format('REVOKE ALL PRIVILEGES ON %s %I.%I(%s) FROM PUBLIC',
      CASE WHEN item.prokind = 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
      item.nspname, item.proname, item.arguments);
    FOREACH runtime_role IN ARRAY ARRAY[
      'elmpay_edge_gateway','elmpay_worker','elmpay_risk_engine',
      'elmpay_webhook_processor','elmpay_admin_web','elmpay_partition_precreator',
      'elmpay_archive_verifier','elmpay_partition_detacher'
    ] LOOP
      EXECUTE format('REVOKE ALL PRIVILEGES ON %s %I.%I(%s) FROM %I',
        CASE WHEN item.prokind = 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
        item.nspname, item.proname, item.arguments, runtime_role);
    END LOOP;
  END LOOP;
END;
$elmpay$;

-- Edge gateway: merchant/payment/refund/checkout/webhook ingress and its local read model.
GRANT SELECT, INSERT, UPDATE ON tenant_registry, project_registry, project_quota,
  merchant_profile, merchant_onboarding, merchant_onboarding_step TO elmpay_edge_gateway;
GRANT SELECT, INSERT ON merchant_verification_decision, tenant_authority_evidence_nonce,
  payment_action_receipt, refund_action_receipt, provider_effect_expectation,
  checkout_session, payment_intent_metadata TO elmpay_edge_gateway;
GRANT INSERT ON merchant_control_audit, merchant_tenant_authority_evidence_audit,
  checkout_provider_sdk_audit, admin_action_diagnostic_audit TO elmpay_edge_gateway;
GRANT SELECT ON provider_account, provider_capability, routing_policy_assignment,
  routing_policy_version, routing_policy_rule, admin_action_dispatch, admin_approval,
  admin_diagnostic_snapshot TO elmpay_edge_gateway;
GRANT SELECT, INSERT ON routing_decision, outbox_event TO elmpay_edge_gateway;
GRANT SELECT, INSERT, UPDATE ON payment_intent, payment_attempt, refund,
  event_aggregate_revision, provider_call_circuit, payment_projection_checkpoint,
  payment_status_read_model TO elmpay_edge_gateway;
GRANT DELETE ON payment_status_read_model TO elmpay_edge_gateway;
GRANT SELECT, INSERT, DELETE ON provider_call_outcome TO elmpay_edge_gateway;
GRANT SELECT, INSERT, DELETE ON payment_timeline_event TO elmpay_edge_gateway;
GRANT SELECT, INSERT ON provider_webhook_inbox TO elmpay_edge_gateway;
GRANT USAGE ON SEQUENCE outbox_event_sequence_no_seq TO elmpay_edge_gateway;

-- Long-running worker: exact callable relay, billing, ledger, reconciliation, audit-anchor,
-- webhook-delivery and payment-timeline paths.  It owns no partition DDL or domain admin path.
GRANT SELECT, INSERT, UPDATE ON outbox_event, event_aggregate_revision,
  consumer_event_inbox, financial_runtime_job, reconciliation_schedule_cursor,
  ledger_event_revision_guard, payment_projection_checkpoint TO elmpay_worker;
GRANT SELECT, UPDATE ON billing_subscription, dunning_case,
  webhook_delivery_outbox TO elmpay_worker;
GRANT SELECT, INSERT ON subscription_billing_cycle, recon_run, recon_match,
  reconciliation_fact_snapshot, reconciliation_fact_snapshot_member,
  ledger_transaction, ledger_entry TO elmpay_worker;
GRANT SELECT ON billing_plan, payment_intent, refund, provider_account,
  provider_capability, statement_file, statement_row, ledger_account,
  ledger_posting_policy, ledger_posting_account_mapping, audit_event,
  webhook_endpoint, webhook_signing_key TO elmpay_worker;
GRANT INSERT ON recon_exception_current, recon_exception_action, recon_exception_origin,
  audit_anchor_receipt, webhook_delivery_dead_letter TO elmpay_worker;
GRANT SELECT, INSERT, UPDATE ON audit_anchor_request TO elmpay_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON payment_status_read_model TO elmpay_worker;
GRANT SELECT, INSERT, DELETE ON payment_timeline_event TO elmpay_worker;
GRANT USAGE ON SEQUENCE outbox_event_sequence_no_seq TO elmpay_worker;

-- Risk service exact JDBC manifest.
GRANT SELECT, INSERT, UPDATE ON risk_runtime_nonce, risk_runtime_rule_set,
  risk_runtime_capability_health, risk_runtime_operation_request,
  event_aggregate_revision TO elmpay_risk_engine;
GRANT INSERT ON risk_runtime_signal_snapshot, risk_runtime_model_result,
  risk_runtime_case_resolution, risk_runtime_audit, outbox_event TO elmpay_risk_engine;
GRANT SELECT, INSERT ON risk_runtime_decision TO elmpay_risk_engine;
GRANT INSERT, UPDATE ON risk_runtime_list_entry TO elmpay_risk_engine;
GRANT USAGE ON SEQUENCE risk_runtime_audit_sequence_no_seq,
  outbox_event_sequence_no_seq TO elmpay_risk_engine;

-- Webhook processor owns only the durable inbox/effect transaction and bound payment facts.
GRANT SELECT, UPDATE ON provider_webhook_inbox TO elmpay_webhook_processor;
GRANT SELECT, INSERT ON provider_webhook_effect_commit, provider_effect_application
  TO elmpay_webhook_processor;
GRANT INSERT ON outbox_event TO elmpay_webhook_processor;
GRANT SELECT ON provider_account, provider_effect_expectation TO elmpay_webhook_processor;
GRANT SELECT, UPDATE ON payment_intent, payment_attempt, refund TO elmpay_webhook_processor;
GRANT SELECT, INSERT, UPDATE ON provider_effect_target_clock,
  event_aggregate_revision TO elmpay_webhook_processor;
GRANT USAGE ON SEQUENCE outbox_event_sequence_no_seq TO elmpay_webhook_processor;

-- Admin web owns approval/session/dispatch state; it never writes domain-owner tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_dpop_nonce, admin_dpop_replay,
  admin_dispatch_signal TO elmpay_admin_web;
GRANT SELECT, INSERT, UPDATE ON admin_approval, admin_action_dispatch,
  admin_diagnostic_snapshot TO elmpay_admin_web;
GRANT SELECT, INSERT ON admin_approval_audit TO elmpay_admin_web;
GRANT INSERT ON admin_access_audit TO elmpay_admin_web;
GRANT USAGE ON SEQUENCE admin_approval_audit_sequence_no_seq,
  admin_access_audit_sequence_no_seq TO elmpay_admin_web;

-- Runtime roles mutate the shared admin queue only through the versioned DB API.
GRANT EXECUTE ON FUNCTION
  elmpay_admin_claim_command(text,bigint),
  elmpay_admin_complete_command(uuid,uuid,text,bigint,uuid,text),
  elmpay_admin_retry_command(uuid,uuid,text,bigint,text,text,timestamptz,boolean),
  elmpay_admin_block_command(uuid,uuid,text,bigint,text,text),
  elmpay_admin_find_effect_receipt(uuid,text)
TO elmpay_edge_gateway, elmpay_risk_engine, elmpay_worker;
GRANT EXECUTE ON FUNCTION
  elmpay_admin_enqueue_command(uuid,uuid,uuid,text,text,text,text,text,text,text,text,bigint,text,text,timestamptz,bigint),
  elmpay_admin_observe_command(uuid,text),
  elmpay_admin_observe_effect_receipt(uuid,uuid,text,uuid,text,text,text,text,text,text,text,bigint,text,text,timestamptz,bigint),
  elmpay_resolve_webhook_ingress_endpoint(text)
TO elmpay_edge_gateway;
GRANT EXECUTE ON FUNCTION elmpay_active_worker_scopes(uuid,uuid,integer),
  elmpay_apply_admin_rollout_approval(uuid,uuid,text,bigint,uuid)
TO elmpay_worker;
GRANT EXECUTE ON FUNCTION elmpay_claimable_webhook_tenants(text,integer,timestamptz)
TO elmpay_webhook_processor;

-- Archive/partition credentials have no base-table privileges.
GRANT EXECUTE ON FUNCTION elmpay_ensure_archive_partitions(date,integer,text,text)
TO elmpay_partition_precreator;
GRANT EXECUTE ON FUNCTION
  elmpay_record_archive_tenant_receipt(uuid,text,text,text,text,text,text,text,bytea,timestamptz,timestamptz),
  elmpay_record_archive_partition_release(uuid,text,integer,text,text,text,text,text,text,text,bytea,timestamptz,timestamptz),
  elmpay_record_archive_detach_authorization(text,uuid,text,text,text,text,text,text,text,text,text,bytea,text,text,bytea,timestamptz,timestamptz)
TO elmpay_archive_verifier;
GRANT EXECUTE ON FUNCTION elmpay_detach_archive_partition(text,uuid,text),
  elmpay_observe_archive_partition_detach(text,uuid,text)
TO elmpay_partition_detacher;

DO $elmpay$
BEGIN
  EXECUTE format('COMMENT ON DATABASE %I IS %L', current_database(),
    'V107 exact runtime ACL manifest; runtime roles own no objects and PUBLIC routines are revoked');
END;
$elmpay$;
