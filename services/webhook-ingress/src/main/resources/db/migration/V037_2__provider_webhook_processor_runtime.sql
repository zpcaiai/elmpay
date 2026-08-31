-- Bounded tenant discovery for the dedicated webhook processor. The function exposes only
-- tenant identifiers with due verified work; callback bodies and payment facts remain behind RLS.
CREATE OR REPLACE FUNCTION elmpay_claimable_webhook_tenants(
    after_tenant text,
    maximum_tenants integer,
    due_at timestamptz)
RETURNS TABLE (tenant_id varchar(64))
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $elmpay$
BEGIN
    IF maximum_tenants < 1 OR maximum_tenants > 1000 THEN
        RAISE EXCEPTION 'maximum_tenants must be 1..1000';
    END IF;
    IF after_tenant IS NOT NULL
       AND after_tenant !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'after_tenant must be a canonical UUID';
    END IF;
    RETURN QUERY
    SELECT DISTINCT inbox.tenant_id
      FROM public.provider_webhook_inbox inbox
     WHERE inbox.terminal_failure = FALSE
       AND inbox.processing_attempts < 100
       AND inbox.canonical_payload_sha256 IS NOT NULL
       AND inbox.verification_digest IS NOT NULL
       AND (after_tenant IS NULL OR inbox.tenant_id > after_tenant)
       AND (
           (inbox.processing_status IN ('VERIFIED', 'FAILED')
            AND COALESCE(inbox.next_attempt_at, inbox.received_at) <= due_at)
           OR
           (inbox.processing_status = 'PROCESSING'
            AND inbox.lease_expires_at <= due_at)
       )
     ORDER BY inbox.tenant_id
     LIMIT maximum_tenants;
END;
$elmpay$;

REVOKE ALL ON FUNCTION elmpay_claimable_webhook_tenants(text, integer, timestamptz)
    FROM PUBLIC;

-- Database provisioning creates this NOLOGIN role and grants it only to the mounted workload
-- login. A developer database without that role remains fail closed until explicitly provisioned.
DO $elmpay$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'elmpay_webhook_processor') THEN
        GRANT EXECUTE ON FUNCTION
            elmpay_claimable_webhook_tenants(text, integer, timestamptz)
            TO elmpay_webhook_processor;
    END IF;
END;
$elmpay$;

-- Rollback: revoke and drop elmpay_claimable_webhook_tenants. Processing/application facts remain.
