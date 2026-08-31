-- B13 additive hardening.  The long-running worker never receives DDL.  Monthly
-- precreation, independent receipt ingestion and detach are three distinct identities.

DO $elmpay$
BEGIN
    IF (SELECT count(*)
          FROM pg_roles role
         WHERE role.rolname IN ('elmpay_partition_precreator',
                                'elmpay_archive_verifier',
                                'elmpay_partition_detacher')
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
              WHERE membership.member = role.oid)) <> 3 THEN
        RAISE EXCEPTION 'archive maintenance roles must be provisioned before V106'
            USING ERRCODE = '42501';
    END IF;
END;
$elmpay$;

CREATE SCHEMA IF NOT EXISTS elmpay_archive_detached AUTHORIZATION elmpay_migrator;
REVOKE ALL ON SCHEMA elmpay_archive_detached FROM PUBLIC, elmpay_edge_gateway,
    elmpay_worker, elmpay_risk_engine, elmpay_webhook_processor, elmpay_admin_web,
    elmpay_partition_precreator, elmpay_archive_verifier, elmpay_partition_detacher;
DO $elmpay$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_namespace namespace
        JOIN pg_roles owner ON owner.oid = namespace.nspowner
        WHERE namespace.nspname = 'elmpay_archive_detached'
          AND owner.rolname = 'elmpay_migrator')
       OR EXISTS (
         SELECT 1
           FROM pg_namespace namespace,
                LATERAL aclexplode(COALESCE(
                  namespace.nspacl, acldefault('n', namespace.nspowner))) acl
          WHERE namespace.nspname = 'elmpay_archive_detached'
            AND acl.grantee = 0
            AND acl.privilege_type IN ('USAGE','CREATE')) THEN
        RAISE EXCEPTION 'detached archive schema ownership or PUBLIC ACL is invalid'
            USING ERRCODE = '42501';
    END IF;
END;
$elmpay$;

CREATE TABLE tenant_archive_partition_tenant (
    partition_name text NOT NULL
        CHECK (partition_name ~ '^tenant_archive_fact_[0-9]{6}$'),
    tenant_id uuid NOT NULL,
    first_seen_at timestamptz NOT NULL,
    PRIMARY KEY (partition_name, tenant_id)
);

-- Backfill an exact tenant inventory.  The migration role owns the table but FORCE RLS on
-- tenant_archive_fact intentionally applies to the owner, so the exclusive migration session
-- temporarily removes FORCE while copying only the two non-sensitive inventory fields.
ALTER TABLE tenant_archive_fact NO FORCE ROW LEVEL SECURITY;
INSERT INTO tenant_archive_partition_tenant(partition_name, tenant_id, first_seen_at)
SELECT tableoid::regclass::text, tenant_id, min(created_at)
  FROM tenant_archive_fact
 GROUP BY tableoid, tenant_id
ON CONFLICT DO NOTHING;
ALTER TABLE tenant_archive_fact FORCE ROW LEVEL SECURITY;

CREATE TABLE tenant_archive_tenant_receipt (
    tenant_id uuid NOT NULL,
    partition_name text NOT NULL,
    object_uri text NOT NULL CHECK (
        object_uri ~ '^object-storage://[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?/[A-Za-z0-9._~/-]{1,1900}$'
        AND object_uri !~ '[?#@%]'
        AND position('//' in substring(object_uri from 18)) = 0
        AND object_uri !~ '/[.][.]?(/|$)'),
    manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    object_digest char(64) NOT NULL CHECK (object_digest ~ '^[0-9a-f]{64}$'),
    canonical_receipt_digest char(64) NOT NULL
        CHECK (canonical_receipt_digest ~ '^[0-9a-f]{64}$'),
    verifier_key_id text NOT NULL CHECK (verifier_key_id ~ '^[A-Za-z0-9._:-]{3,128}$'),
    nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    verified_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, partition_name, canonical_receipt_digest),
    UNIQUE (verifier_key_id, nonce),
    FOREIGN KEY (partition_name, tenant_id)
        REFERENCES tenant_archive_partition_tenant(partition_name, tenant_id),
    CHECK (issued_at < expires_at AND expires_at <= issued_at + interval '30 days')
);

CREATE TABLE tenant_archive_verifier_nonce (
    verifier_key_id text NOT NULL CHECK (verifier_key_id ~ '^[A-Za-z0-9._:-]{3,128}$'),
    nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
    receipt_type text NOT NULL
        CHECK (receipt_type IN ('TENANT_ARCHIVE_EXPORT_V1','ARCHIVE_PARTITION_RELEASE_V1',
                                'ARCHIVE_PARTITION_DETACH_AUTHORIZATION_V1')),
    canonical_receipt_digest char(64) NOT NULL
        CHECK (canonical_receipt_digest ~ '^[0-9a-f]{64}$'),
    verified_at timestamptz NOT NULL,
    PRIMARY KEY (verifier_key_id, nonce)
);

CREATE TABLE tenant_archive_partition_release (
    release_id uuid PRIMARY KEY,
    partition_name text NOT NULL
        CHECK (partition_name ~ '^tenant_archive_fact_[0-9]{6}$'),
    tenant_count integer NOT NULL CHECK (tenant_count > 0),
    receipt_set_binding text NOT NULL
        CHECK (octet_length(receipt_set_binding) BETWEEN 64 AND 1048576
            AND receipt_set_binding ~ '^[0-9a-f]{64}(,[0-9a-f]{64})*$'),
    receipt_set_digest char(64) NOT NULL CHECK (receipt_set_digest ~ '^[0-9a-f]{64}$'),
    aggregate_manifest_binding text NOT NULL
        CHECK (octet_length(aggregate_manifest_binding) BETWEEN 101 AND 2097152
            AND aggregate_manifest_binding ~
                '^[0-9a-f-]{36}:[0-9a-f]{64}(,[0-9a-f-]{36}:[0-9a-f]{64})*$'),
    aggregate_manifest_digest char(64) NOT NULL
        CHECK (aggregate_manifest_digest ~ '^[0-9a-f]{64}$'),
    canonical_receipt_digest char(64) NOT NULL
        CHECK (canonical_receipt_digest ~ '^[0-9a-f]{64}$'),
    verifier_key_id text NOT NULL CHECK (verifier_key_id ~ '^[A-Za-z0-9._:-]{3,128}$'),
    nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    verified_at timestamptz NOT NULL,
    detached_at timestamptz,
    UNIQUE (verifier_key_id, nonce),
    CHECK (issued_at < expires_at AND expires_at <= issued_at + interval '30 days'),
    CHECK (detached_at IS NULL OR detached_at >= verified_at)
);

ALTER TABLE tenant_archive_partition_release
    ADD CONSTRAINT tenant_archive_partition_release_identity_key
    UNIQUE (release_id, partition_name);

CREATE TABLE tenant_archive_detach_authorization (
    release_id uuid NOT NULL,
    partition_name text NOT NULL
        CHECK (partition_name ~ '^tenant_archive_fact_[0-9]{6}$'),
    actor_id text NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9._:-]{3,128}$'),
    approver_id text NOT NULL CHECK (approver_id ~ '^[A-Za-z0-9._:-]{3,128}$'),
    reason text NOT NULL CHECK (length(reason) BETWEEN 8 AND 512
        AND reason !~ '[[:cntrl:]]'),
    ticket_id text NOT NULL CHECK (ticket_id ~ '^[A-Za-z0-9._:-]{3,128}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    canonical_authorization_digest char(64) NOT NULL
        CHECK (canonical_authorization_digest ~ '^[0-9a-f]{64}$'),
    partition_release_key_id text NOT NULL
        CHECK (partition_release_key_id ~ '^[A-Za-z0-9._:-]{3,128}$'),
    actor_verifier_key_id text NOT NULL
        CHECK (actor_verifier_key_id ~ '^[A-Za-z0-9._:-]{3,128}$'),
    actor_nonce text NOT NULL CHECK (actor_nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
    actor_signature bytea NOT NULL CHECK (octet_length(actor_signature) = 64),
    approver_verifier_key_id text NOT NULL
        CHECK (approver_verifier_key_id ~ '^[A-Za-z0-9._:-]{3,128}$'),
    approver_nonce text NOT NULL CHECK (approver_nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
    approver_signature bytea NOT NULL CHECK (octet_length(approver_signature) = 64),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    verified_at timestamptz NOT NULL,
    executed_at timestamptz,
    PRIMARY KEY (release_id, partition_name, canonical_authorization_digest),
    UNIQUE (actor_verifier_key_id, actor_nonce),
    UNIQUE (approver_verifier_key_id, approver_nonce),
    FOREIGN KEY (release_id, partition_name)
        REFERENCES tenant_archive_partition_release(release_id, partition_name),
    CHECK (actor_id <> approver_id),
    CHECK (actor_verifier_key_id <> approver_verifier_key_id),
    CHECK (partition_release_key_id <> actor_verifier_key_id
        AND partition_release_key_id <> approver_verifier_key_id),
    CHECK (issued_at < expires_at AND expires_at <= issued_at + interval '15 minutes'),
    CHECK (executed_at IS NULL OR executed_at >= verified_at)
);

ALTER TABLE tenant_archive_partition_tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_archive_partition_tenant FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_archive_partition_tenant_internal_policy
    ON tenant_archive_partition_tenant
    USING (session_user IN ('elmpay_migrator','elmpay_archive_verifier',
                            'elmpay_partition_detacher'))
    WITH CHECK (session_user = 'elmpay_migrator'
        OR (session_user IN ('elmpay_edge_gateway','elmpay_worker')
            AND tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid));

ALTER TABLE tenant_archive_tenant_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_archive_tenant_receipt FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_archive_tenant_receipt_internal_policy
    ON tenant_archive_tenant_receipt
    USING (session_user IN ('elmpay_migrator','elmpay_archive_verifier',
                            'elmpay_partition_detacher'))
    WITH CHECK (session_user IN ('elmpay_migrator','elmpay_archive_verifier'));

ALTER TABLE tenant_archive_verifier_nonce ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_archive_verifier_nonce FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_archive_verifier_nonce_internal_policy
    ON tenant_archive_verifier_nonce
    USING (session_user IN ('elmpay_migrator','elmpay_archive_verifier',
                            'elmpay_partition_detacher'))
    WITH CHECK (session_user IN ('elmpay_migrator','elmpay_archive_verifier'));

ALTER TABLE tenant_archive_partition_release ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_archive_partition_release FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_archive_partition_release_internal_policy
    ON tenant_archive_partition_release
    USING (session_user IN ('elmpay_migrator','elmpay_archive_verifier',
                            'elmpay_partition_detacher'))
    WITH CHECK (session_user IN ('elmpay_migrator','elmpay_archive_verifier',
                                 'elmpay_partition_detacher'));

ALTER TABLE tenant_archive_detach_authorization ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_archive_detach_authorization FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_archive_detach_authorization_internal_policy
    ON tenant_archive_detach_authorization
    USING (session_user IN ('elmpay_migrator','elmpay_archive_verifier',
                            'elmpay_partition_detacher'))
    WITH CHECK (session_user IN ('elmpay_migrator','elmpay_archive_verifier',
                                 'elmpay_partition_detacher'));

CREATE FUNCTION elmpay_register_archive_partition_tenant()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
BEGIN
    -- elmpay.archive-maintenance.v1:partition-tenant-inventory
    IF TG_TABLE_NAME !~ '^tenant_archive_fact_[0-9]{6}$'
       OR NEW.tenant_id IS DISTINCT FROM
            NULLIF(current_setting('app.tenant_id', true), '')::uuid THEN
        RAISE EXCEPTION 'archive fact lacks an exact tenant partition context'
            USING ERRCODE = '42501';
    END IF;
    INSERT INTO tenant_archive_partition_tenant(partition_name, tenant_id, first_seen_at)
    VALUES (TG_TABLE_NAME, NEW.tenant_id, clock_timestamp())
    ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$elmpay$;

DROP TRIGGER IF EXISTS tenant_archive_partition_tenant_inventory ON tenant_archive_fact;
CREATE TRIGGER tenant_archive_partition_tenant_inventory
AFTER INSERT ON tenant_archive_fact
FOR EACH ROW EXECUTE FUNCTION elmpay_register_archive_partition_tenant();

CREATE FUNCTION elmpay_ensure_archive_partitions(
    p_first_month date, p_count integer, p_actor_id text, p_ticket_id text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_month date;
    v_offset integer;
    v_partition text;
    v_created integer := 0;
BEGIN
    -- elmpay.archive-maintenance.v1:bounded-precreate-only
    IF session_user <> 'elmpay_partition_precreator'
       OR p_first_month <> date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC')::date
       OR p_count < 1 OR p_count > 24
       OR p_actor_id !~ '^[A-Za-z0-9._:-]{3,128}$'
       OR p_ticket_id !~ '^[A-Za-z0-9._:-]{3,128}$' THEN
        RAISE EXCEPTION 'partition precreation input is not authorized'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('elmpay:tenant_archive_partition', 0));
    FOR v_offset IN 0..p_count - 1 LOOP
        v_month := (p_first_month + make_interval(months => v_offset))::date;
        v_partition := 'tenant_archive_fact_' || to_char(v_month, 'YYYYMM');
        IF to_regclass('public.' || v_partition) IS NULL THEN
            EXECUTE format(
                'CREATE TABLE public.%I PARTITION OF public.tenant_archive_fact '
                'FOR VALUES FROM (%L) TO (%L)',
                v_partition, v_month, (v_month + interval '1 month')::date);
            INSERT INTO tenant_partition_change
                (partition_name, action, actor_id, approver_id, reason, ticket_id, occurred_at)
            VALUES (v_partition, 'CREATE', p_actor_id, NULL,
                    'bounded dedicated partition precreation', p_ticket_id,
                    clock_timestamp());
            v_created := v_created + 1;
        END IF;
    END LOOP;
    RETURN v_created;
END;
$elmpay$;

CREATE FUNCTION elmpay_record_archive_tenant_receipt(
    p_tenant_id uuid, p_partition_name text, p_object_uri text,
    p_manifest_digest text, p_object_digest text, p_canonical_receipt_digest text,
    p_verifier_key_id text, p_nonce text, p_signature bytea,
    p_issued_at timestamptz, p_expires_at timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
    -- elmpay.archive-maintenance.v1:independent-ed25519-tenant-receipt
    IF session_user <> 'elmpay_archive_verifier'
       OR p_issued_at > v_now + interval '1 minute' OR p_expires_at <= v_now
       OR p_expires_at > p_issued_at + interval '30 days' THEN
        RAISE EXCEPTION 'archive tenant receipt is not currently valid'
            USING ERRCODE = '42501';
    END IF;
    INSERT INTO tenant_archive_verifier_nonce
        (verifier_key_id, nonce, receipt_type, canonical_receipt_digest, verified_at)
    VALUES (p_verifier_key_id, p_nonce, 'TENANT_ARCHIVE_EXPORT_V1',
            p_canonical_receipt_digest, v_now);
    INSERT INTO tenant_archive_tenant_receipt
        (tenant_id, partition_name, object_uri, manifest_digest, object_digest,
         canonical_receipt_digest, verifier_key_id, nonce, signature, issued_at,
         expires_at, verified_at)
    VALUES (p_tenant_id, p_partition_name, p_object_uri, p_manifest_digest,
            p_object_digest, p_canonical_receipt_digest, p_verifier_key_id, p_nonce,
            p_signature, p_issued_at, p_expires_at, v_now);
END;
$elmpay$;

CREATE FUNCTION elmpay_record_archive_partition_release(
    p_release_id uuid, p_partition_name text, p_tenant_count integer,
    p_receipt_set_binding text, p_receipt_set_digest text,
    p_aggregate_manifest_binding text, p_aggregate_manifest_digest text,
    p_canonical_receipt_digest text, p_verifier_key_id text, p_nonce text,
    p_signature bytea, p_issued_at timestamptz, p_expires_at timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_now timestamptz := clock_timestamp();
    v_inventory_count integer;
    v_receipt_count integer;
    v_receipt_set_binding text;
    v_aggregate_manifest_binding text;
BEGIN
    -- elmpay.archive-maintenance.v1:independent-ed25519-all-tenant-release
    IF session_user <> 'elmpay_archive_verifier'
       OR p_issued_at > v_now + interval '1 minute' OR p_expires_at <= v_now
       OR p_expires_at > p_issued_at + interval '30 days' THEN
        RAISE EXCEPTION 'archive partition release is not currently valid'
            USING ERRCODE = '42501';
    END IF;
    SELECT count(*) INTO v_inventory_count
      FROM tenant_archive_partition_tenant
     WHERE partition_name = p_partition_name;
    SELECT count(*) INTO v_receipt_count
      FROM (SELECT DISTINCT ON (candidate.tenant_id) candidate.*
              FROM tenant_archive_tenant_receipt candidate
             WHERE candidate.partition_name = p_partition_name
               AND candidate.expires_at > v_now
             ORDER BY candidate.tenant_id, candidate.issued_at DESC,
                      candidate.canonical_receipt_digest DESC) receipt
      JOIN tenant_archive_partition_tenant inventory
        ON inventory.partition_name = receipt.partition_name
       AND inventory.tenant_id = receipt.tenant_id
     WHERE receipt.partition_name = p_partition_name
       AND receipt.expires_at > v_now;
    SELECT string_agg(receipt.canonical_receipt_digest::text, ',' ORDER BY receipt.tenant_id)
      INTO v_receipt_set_binding
      FROM (SELECT DISTINCT ON (candidate.tenant_id) candidate.*
              FROM tenant_archive_tenant_receipt candidate
             WHERE candidate.partition_name = p_partition_name
               AND candidate.expires_at > v_now
             ORDER BY candidate.tenant_id, candidate.issued_at DESC,
                      candidate.canonical_receipt_digest DESC) receipt
      JOIN tenant_archive_partition_tenant inventory
        ON inventory.partition_name = receipt.partition_name
       AND inventory.tenant_id = receipt.tenant_id
     WHERE receipt.partition_name = p_partition_name
       AND receipt.expires_at > v_now;
    SELECT string_agg(receipt.tenant_id::text || ':' || receipt.manifest_digest::text,
                      ',' ORDER BY receipt.tenant_id)
      INTO v_aggregate_manifest_binding
      FROM (SELECT DISTINCT ON (candidate.tenant_id) candidate.*
              FROM tenant_archive_tenant_receipt candidate
             WHERE candidate.partition_name = p_partition_name
               AND candidate.expires_at > v_now
             ORDER BY candidate.tenant_id, candidate.issued_at DESC,
                      candidate.canonical_receipt_digest DESC) receipt
      JOIN tenant_archive_partition_tenant inventory
        ON inventory.partition_name = receipt.partition_name
       AND inventory.tenant_id = receipt.tenant_id
     WHERE receipt.partition_name = p_partition_name
       AND receipt.expires_at > v_now;
    IF v_inventory_count < 1 OR v_inventory_count <> p_tenant_count
       OR v_receipt_count <> v_inventory_count
       OR v_receipt_set_binding IS DISTINCT FROM p_receipt_set_binding
       OR encode(sha256(convert_to(v_receipt_set_binding, 'UTF8')), 'hex') <>
            p_receipt_set_digest
       OR v_aggregate_manifest_binding IS DISTINCT FROM p_aggregate_manifest_binding
       OR encode(sha256(convert_to(v_aggregate_manifest_binding, 'UTF8')), 'hex') <>
            p_aggregate_manifest_digest
       OR EXISTS (
         SELECT 1
           FROM (SELECT DISTINCT ON (candidate.tenant_id) candidate.*
                   FROM tenant_archive_tenant_receipt candidate
                  WHERE candidate.partition_name = p_partition_name
                    AND candidate.expires_at > v_now
                  ORDER BY candidate.tenant_id, candidate.issued_at DESC,
                           candidate.canonical_receipt_digest DESC) receipt
          WHERE receipt.verifier_key_id = p_verifier_key_id)
       OR EXISTS (
         SELECT 1 FROM tenant_archive_partition_tenant inventory
          WHERE inventory.partition_name = p_partition_name
            AND NOT EXISTS (
              SELECT 1
                FROM (SELECT DISTINCT ON (candidate.tenant_id) candidate.*
                        FROM tenant_archive_tenant_receipt candidate
                       WHERE candidate.partition_name = p_partition_name
                         AND candidate.expires_at > v_now
                       ORDER BY candidate.tenant_id, candidate.issued_at DESC,
                                candidate.canonical_receipt_digest DESC) receipt
               WHERE receipt.tenant_id = inventory.tenant_id)) THEN
        RAISE EXCEPTION 'all partition tenants require current independent receipts'
            USING ERRCODE = '55000';
    END IF;
    INSERT INTO tenant_archive_verifier_nonce
        (verifier_key_id, nonce, receipt_type, canonical_receipt_digest, verified_at)
    VALUES (p_verifier_key_id, p_nonce, 'ARCHIVE_PARTITION_RELEASE_V1',
            p_canonical_receipt_digest, v_now);
    INSERT INTO tenant_archive_partition_release
        (release_id, partition_name, tenant_count, receipt_set_binding, receipt_set_digest,
         aggregate_manifest_binding, aggregate_manifest_digest,
         canonical_receipt_digest, verifier_key_id,
         nonce, signature, issued_at, expires_at, verified_at)
    VALUES (p_release_id, p_partition_name, p_tenant_count, p_receipt_set_binding,
            p_receipt_set_digest,
            p_aggregate_manifest_binding, p_aggregate_manifest_digest,
            p_canonical_receipt_digest,
            p_verifier_key_id, p_nonce, p_signature, p_issued_at, p_expires_at, v_now);
END;
$elmpay$;

CREATE FUNCTION elmpay_record_archive_detach_authorization(
    p_partition_name text, p_release_id uuid, p_actor_id text, p_approver_id text,
    p_reason text, p_ticket_id text, p_policy_digest text,
    p_canonical_authorization_digest text, p_partition_release_key_id text,
    p_actor_verifier_key_id text, p_actor_nonce text, p_actor_signature bytea,
    p_approver_verifier_key_id text, p_approver_nonce text, p_approver_signature bytea,
    p_issued_at timestamptz, p_expires_at timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_now timestamptz := clock_timestamp();
BEGIN
    -- elmpay.archive-maintenance.v1:independent-ed25519-detach-authorization
    IF session_user <> 'elmpay_archive_verifier'
       OR p_partition_name !~ '^tenant_archive_fact_[0-9]{6}$'
       OR p_actor_id !~ '^[A-Za-z0-9._:-]{3,128}$'
       OR p_approver_id !~ '^[A-Za-z0-9._:-]{3,128}$'
       OR p_actor_id = p_approver_id
       OR p_reason IS NULL OR length(p_reason) NOT BETWEEN 8 AND 512
       OR p_reason ~ '[[:cntrl:]]'
       OR p_ticket_id !~ '^[A-Za-z0-9._:-]{3,128}$'
       OR p_policy_digest !~ '^[0-9a-f]{64}$'
       OR p_canonical_authorization_digest !~ '^[0-9a-f]{64}$'
       OR p_partition_release_key_id !~ '^[A-Za-z0-9._:-]{3,128}$'
       OR p_actor_verifier_key_id !~ '^[A-Za-z0-9._:-]{3,128}$'
       OR p_actor_nonce !~ '^[A-Za-z0-9_-]{16,128}$'
       OR octet_length(p_actor_signature) <> 64
       OR p_approver_verifier_key_id !~ '^[A-Za-z0-9._:-]{3,128}$'
       OR p_approver_nonce !~ '^[A-Za-z0-9_-]{16,128}$'
       OR octet_length(p_approver_signature) <> 64
       OR p_actor_verifier_key_id = p_approver_verifier_key_id
       OR p_partition_release_key_id IN
            (p_actor_verifier_key_id, p_approver_verifier_key_id)
       OR p_issued_at > v_now + interval '1 minute'
       OR p_expires_at <= v_now
       OR p_expires_at > p_issued_at + interval '15 minutes' THEN
        RAISE EXCEPTION 'partition detach authorization is invalid'
            USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM tenant_archive_partition_release release
         WHERE release.release_id = p_release_id
           AND release.partition_name = p_partition_name
           AND release.verifier_key_id = p_partition_release_key_id
           AND release.detached_at IS NULL AND release.expires_at > v_now) THEN
        RAISE EXCEPTION 'partition release is unavailable for detach authorization'
            USING ERRCODE = '55000';
    END IF;
    INSERT INTO tenant_archive_verifier_nonce
        (verifier_key_id, nonce, receipt_type, canonical_receipt_digest, verified_at)
    VALUES (p_actor_verifier_key_id, p_actor_nonce,
            'ARCHIVE_PARTITION_DETACH_AUTHORIZATION_V1',
            p_canonical_authorization_digest, v_now);
    INSERT INTO tenant_archive_verifier_nonce
        (verifier_key_id, nonce, receipt_type, canonical_receipt_digest, verified_at)
    VALUES (p_approver_verifier_key_id, p_approver_nonce,
            'ARCHIVE_PARTITION_DETACH_AUTHORIZATION_V1',
            p_canonical_authorization_digest, v_now);
    INSERT INTO tenant_archive_detach_authorization
        (release_id, partition_name, actor_id, approver_id, reason, ticket_id,
         policy_digest, canonical_authorization_digest, partition_release_key_id,
         actor_verifier_key_id, actor_nonce, actor_signature,
         approver_verifier_key_id, approver_nonce, approver_signature,
         issued_at, expires_at, verified_at, executed_at)
    VALUES (p_release_id, p_partition_name, p_actor_id, p_approver_id, p_reason,
            p_ticket_id, p_policy_digest, p_canonical_authorization_digest,
            p_partition_release_key_id, p_actor_verifier_key_id, p_actor_nonce,
            p_actor_signature, p_approver_verifier_key_id, p_approver_nonce,
            p_approver_signature, p_issued_at, p_expires_at, v_now, NULL);
END;
$elmpay$;

CREATE FUNCTION elmpay_detach_archive_partition(
    p_partition_name text, p_release_id uuid, p_canonical_authorization_digest text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_now timestamptz := clock_timestamp();
    v_release tenant_archive_partition_release%ROWTYPE;
    v_authorization tenant_archive_detach_authorization%ROWTYPE;
    v_inventory_count integer;
    v_receipt_count integer;
    v_receipt_set_binding text;
    v_aggregate_manifest_binding text;
    v_release_updates integer;
    v_authorization_updates integer;
BEGIN
    -- elmpay.archive-maintenance.v1:separate-all-tenant-detach
    IF session_user <> 'elmpay_partition_detacher'
       OR p_partition_name !~ '^tenant_archive_fact_[0-9]{6}$'
       OR p_canonical_authorization_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'partition detach is not authorized' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('elmpay:tenant_archive_partition', 0));
    SELECT * INTO v_authorization FROM tenant_archive_detach_authorization
     WHERE release_id = p_release_id AND partition_name = p_partition_name
       AND canonical_authorization_digest = p_canonical_authorization_digest
       AND executed_at IS NULL AND expires_at > v_now
     FOR UPDATE;
    SELECT * INTO v_release FROM tenant_archive_partition_release
     WHERE release_id = p_release_id AND partition_name = p_partition_name
       AND detached_at IS NULL AND expires_at > v_now
     FOR UPDATE;
    IF v_authorization.release_id IS NULL OR v_release.release_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_inherits inheritance
        JOIN pg_class child ON child.oid = inheritance.inhrelid
        WHERE inheritance.inhparent = 'public.tenant_archive_fact'::regclass
          AND child.relname = p_partition_name) THEN
        RAISE EXCEPTION 'partition release or live child is unavailable'
            USING ERRCODE = '55000';
    END IF;
    IF v_authorization.partition_release_key_id IS DISTINCT FROM
            v_release.verifier_key_id THEN
        RAISE EXCEPTION 'detach authorization is not bound to this partition release'
            USING ERRCODE = '55000';
    END IF;
    SELECT count(*) INTO v_inventory_count FROM tenant_archive_partition_tenant
     WHERE partition_name = p_partition_name;
    SELECT count(*) INTO v_receipt_count
      FROM (SELECT DISTINCT ON (candidate.tenant_id) candidate.*
              FROM tenant_archive_tenant_receipt candidate
             WHERE candidate.partition_name = p_partition_name
               AND candidate.expires_at > v_now
             ORDER BY candidate.tenant_id, candidate.issued_at DESC,
                      candidate.canonical_receipt_digest DESC) receipt;
    SELECT string_agg(receipt.canonical_receipt_digest::text, ',' ORDER BY receipt.tenant_id)
      INTO v_receipt_set_binding
      FROM (SELECT DISTINCT ON (candidate.tenant_id) candidate.*
              FROM tenant_archive_tenant_receipt candidate
             WHERE candidate.partition_name = p_partition_name
               AND candidate.expires_at > v_now
             ORDER BY candidate.tenant_id, candidate.issued_at DESC,
                      candidate.canonical_receipt_digest DESC) receipt
      JOIN tenant_archive_partition_tenant inventory
        ON inventory.partition_name = receipt.partition_name
       AND inventory.tenant_id = receipt.tenant_id
     WHERE receipt.partition_name = p_partition_name
       AND receipt.expires_at > v_now;
    SELECT string_agg(receipt.tenant_id::text || ':' || receipt.manifest_digest::text,
                      ',' ORDER BY receipt.tenant_id)
      INTO v_aggregate_manifest_binding
      FROM (SELECT DISTINCT ON (candidate.tenant_id) candidate.*
              FROM tenant_archive_tenant_receipt candidate
             WHERE candidate.partition_name = p_partition_name
               AND candidate.expires_at > v_now
             ORDER BY candidate.tenant_id, candidate.issued_at DESC,
                      candidate.canonical_receipt_digest DESC) receipt
      JOIN tenant_archive_partition_tenant inventory
        ON inventory.partition_name = receipt.partition_name
       AND inventory.tenant_id = receipt.tenant_id
     WHERE receipt.partition_name = p_partition_name
       AND receipt.expires_at > v_now;
    IF v_inventory_count <> v_release.tenant_count
       OR v_receipt_count <> v_inventory_count
       OR v_receipt_set_binding IS DISTINCT FROM v_release.receipt_set_binding
       OR encode(sha256(convert_to(v_receipt_set_binding, 'UTF8')), 'hex') <>
            v_release.receipt_set_digest
       OR v_aggregate_manifest_binding IS DISTINCT FROM
            v_release.aggregate_manifest_binding
       OR encode(sha256(convert_to(v_aggregate_manifest_binding, 'UTF8')), 'hex') <>
            v_release.aggregate_manifest_digest
       OR EXISTS (
         SELECT 1 FROM tenant_archive_partition_tenant inventory
          WHERE inventory.partition_name = p_partition_name
            AND NOT EXISTS (
              SELECT 1
                FROM (SELECT DISTINCT ON (candidate.tenant_id) candidate.*
                        FROM tenant_archive_tenant_receipt candidate
                       WHERE candidate.partition_name = p_partition_name
                         AND candidate.expires_at > v_now
                       ORDER BY candidate.tenant_id, candidate.issued_at DESC,
                                candidate.canonical_receipt_digest DESC) receipt
               WHERE receipt.tenant_id = inventory.tenant_id)) THEN
        RAISE EXCEPTION 'partition tenant receipt coverage changed after release'
            USING ERRCODE = '55000';
    END IF;
    EXECUTE format('ALTER TABLE public.tenant_archive_fact DETACH PARTITION public.%I',
                   p_partition_name);
    EXECUTE format('ALTER TABLE public.%I SET SCHEMA elmpay_archive_detached',
                   p_partition_name);
    UPDATE tenant_archive_partition_release SET detached_at = v_now
     WHERE release_id = p_release_id AND detached_at IS NULL;
    GET DIAGNOSTICS v_release_updates = ROW_COUNT;
    INSERT INTO tenant_partition_change
        (partition_name, action, actor_id, approver_id, reason, ticket_id, occurred_at)
    VALUES (p_partition_name, 'DETACH', v_authorization.actor_id,
            v_authorization.approver_id, v_authorization.reason,
            v_authorization.ticket_id, v_now);
    UPDATE tenant_archive_detach_authorization SET executed_at = v_now
     WHERE release_id = p_release_id AND partition_name = p_partition_name
       AND canonical_authorization_digest = p_canonical_authorization_digest
       AND executed_at IS NULL;
    GET DIAGNOSTICS v_authorization_updates = ROW_COUNT;
    IF v_release_updates <> 1 OR v_authorization_updates <> 1 THEN
        RAISE EXCEPTION 'partition detach completion markers were not applied exactly once'
            USING ERRCODE = '55000';
    END IF;
END;
$elmpay$;

CREATE FUNCTION elmpay_observe_archive_partition_detach(
    p_partition_name text, p_release_id uuid,
    p_canonical_authorization_digest text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE v_applied boolean;
BEGIN
    -- elmpay.archive-maintenance.v1:exact-detach-reconciliation
    IF session_user <> 'elmpay_partition_detacher'
       OR p_partition_name !~ '^tenant_archive_fact_[0-9]{6}$'
       OR p_canonical_authorization_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'partition detach observation is not authorized'
            USING ERRCODE = '42501';
    END IF;
    SELECT release.detached_at IS NOT NULL
       AND to_regclass('public.' || p_partition_name) IS NULL
       AND to_regclass('elmpay_archive_detached.' || p_partition_name) IS NOT NULL
      INTO v_applied
      FROM tenant_archive_detach_authorization authorization
      JOIN tenant_archive_partition_release release
        ON release.release_id = authorization.release_id
       AND release.partition_name = authorization.partition_name
     WHERE authorization.release_id = p_release_id
       AND authorization.partition_name = p_partition_name
       AND authorization.canonical_authorization_digest =
            p_canonical_authorization_digest
       AND authorization.executed_at IS NOT NULL;
    RETURN COALESCE(v_applied, false);
END;
$elmpay$;

-- Legacy rows were never cryptographically bound and are not accepted by any new function.
COMMENT ON TABLE tenant_archive_export_receipt IS
    'Legacy untrusted metadata; never authorizes detach. Use signed tenant and partition receipts.';
CREATE FUNCTION elmpay_reject_legacy_archive_receipt_insert()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
    RAISE EXCEPTION 'legacy archive receipt ingestion is disabled' USING ERRCODE = '55000';
END;
$elmpay$;
DROP TRIGGER IF EXISTS tenant_archive_export_receipt_no_insert ON tenant_archive_export_receipt;
CREATE TRIGGER tenant_archive_export_receipt_no_insert
BEFORE INSERT ON tenant_archive_export_receipt
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_legacy_archive_receipt_insert();

REVOKE ALL ON tenant_archive_partition_tenant, tenant_archive_tenant_receipt,
    tenant_archive_partition_release, tenant_archive_verifier_nonce,
    tenant_archive_detach_authorization,
    tenant_archive_export_receipt,
    tenant_partition_change FROM PUBLIC;
REVOKE ALL ON tenant_archive_partition_tenant, tenant_archive_tenant_receipt,
    tenant_archive_partition_release, tenant_archive_verifier_nonce,
    tenant_archive_detach_authorization,
    tenant_archive_export_receipt,
    tenant_partition_change FROM elmpay_worker;
REVOKE ALL ON FUNCTION elmpay_register_archive_partition_tenant(),
    elmpay_ensure_archive_partitions(date,integer,text,text),
    elmpay_record_archive_tenant_receipt(uuid,text,text,text,text,text,text,text,bytea,timestamptz,timestamptz),
    elmpay_record_archive_partition_release(uuid,text,integer,text,text,text,text,text,text,text,bytea,timestamptz,timestamptz),
    elmpay_record_archive_detach_authorization(text,uuid,text,text,text,text,text,text,text,text,text,bytea,text,text,bytea,timestamptz,timestamptz),
    elmpay_detach_archive_partition(text,uuid,text),
    elmpay_observe_archive_partition_detach(text,uuid,text),
    elmpay_reject_legacy_archive_receipt_insert()
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION elmpay_ensure_archive_partitions(date,integer,text,text)
    TO elmpay_partition_precreator;
GRANT EXECUTE ON FUNCTION
    elmpay_record_archive_tenant_receipt(uuid,text,text,text,text,text,text,text,bytea,timestamptz,timestamptz),
    elmpay_record_archive_partition_release(uuid,text,integer,text,text,text,text,text,text,text,bytea,timestamptz,timestamptz),
    elmpay_record_archive_detach_authorization(text,uuid,text,text,text,text,text,text,text,text,text,bytea,text,text,bytea,timestamptz,timestamptz)
    TO elmpay_archive_verifier;
GRANT EXECUTE ON FUNCTION
    elmpay_detach_archive_partition(text,uuid,text)
    TO elmpay_partition_detacher;
GRANT EXECUTE ON FUNCTION
    elmpay_observe_archive_partition_detach(text,uuid,text)
    TO elmpay_partition_detacher;

-- Trigger functions remain non-callable capabilities.  Every exposed definer function has a
-- fixed path, explicit session_user role and a bounded operation.
REVOKE ALL ON FUNCTION elmpay_register_archive_partition_tenant(),
    elmpay_reject_legacy_archive_receipt_insert() FROM PUBLIC;
