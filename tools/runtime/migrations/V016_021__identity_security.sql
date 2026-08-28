CREATE TABLE identity_session (
  session_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  assurance_level text NOT NULL CHECK (assurance_level IN ('AAL1','AAL2','PHISHING_RESISTANT')),
  device_digest char(64) NOT NULL,
  holder_thumbprint char(64) NOT NULL,
  refresh_family uuid NOT NULL,
  refresh_counter bigint NOT NULL DEFAULT 0 CHECK (refresh_counter >= 0),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > issued_at)
);

CREATE TABLE workload_identity (
  spiffe_id text PRIMARY KEY,
  service_name text NOT NULL,
  certificate_thumbprint char(64) NOT NULL UNIQUE,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > issued_at)
);

CREATE TABLE webauthn_credential (
  tenant_id uuid NOT NULL,
  user_id text NOT NULL,
  credential_id text NOT NULL,
  public_key_pem text NOT NULL,
  rp_id text NOT NULL,
  aaguid text NOT NULL,
  sign_count bigint NOT NULL CHECK (sign_count >= 0),
  backup_eligible boolean NOT NULL,
  attestation_receipt_digest char(64) NOT NULL,
  created_at timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, credential_id)
);

CREATE TABLE webauthn_challenge (
  challenge_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  user_id text NOT NULL,
  operation text NOT NULL,
  challenge text NOT NULL UNIQUE,
  origin text NOT NULL,
  rp_id text NOT NULL,
  session_binding char(64) NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);

CREATE TABLE authorization_grant (
  grant_id char(64) PRIMARY KEY,
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  role_name text NOT NULL,
  object_scope text NOT NULL,
  field_scope jsonb NOT NULL,
  proposed_by text NOT NULL,
  approved_by text,
  state text NOT NULL CHECK (state IN ('PROPOSED','ACTIVE','REJECTED','EXPIRED','REVOKED')),
  valid_from timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  payload_digest char(64) NOT NULL,
  created_at timestamptz NOT NULL,
  CHECK (valid_until > valid_from),
  CHECK (approved_by IS NULL OR approved_by <> proposed_by)
);

CREATE TABLE identity_recovery (
  recovery_id char(64) PRIMARY KEY,
  tenant_id uuid NOT NULL,
  subject_id text NOT NULL,
  proposed_by text NOT NULL,
  approved_by text,
  reason text NOT NULL,
  state text NOT NULL CHECK (state IN ('PROPOSED','APPROVED','REJECTED','EXPIRED')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  decided_at timestamptz,
  CHECK (approved_by IS NULL OR approved_by <> proposed_by)
);

CREATE TABLE encrypted_secret_record (
  tenant_id uuid NOT NULL,
  resource_id text NOT NULL,
  purpose text NOT NULL,
  key_reference text NOT NULL,
  key_version text NOT NULL,
  aad_digest char(64) NOT NULL,
  wrapped_data_key bytea NOT NULL,
  nonce bytea NOT NULL,
  ciphertext bytea NOT NULL,
  created_at timestamptz NOT NULL,
  rotated_at timestamptz,
  PRIMARY KEY (tenant_id, resource_id, purpose)
);

CREATE TABLE certificate_inventory (
  serial_number text PRIMARY KEY,
  subject_name text NOT NULL,
  san_names jsonb NOT NULL,
  issuer_name text NOT NULL,
  key_reference text NOT NULL,
  overlap_group text NOT NULL,
  status text NOT NULL CHECK (status IN ('PROPOSED','ACTIVE','OVERLAP','REVOKED','EXPIRED')),
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL,
  proposer text NOT NULL,
  approver text,
  ca_receipt_digest char(64) NOT NULL,
  created_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (not_after > not_before),
  CHECK (approver IS NULL OR approver <> proposer)
);

CREATE TABLE identity_security_audit (
  sequence_no bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid,
  event_type text NOT NULL,
  object_digest char(64) NOT NULL,
  actor_id text NOT NULL,
  previous_hash text NOT NULL,
  audit_hash char(64) NOT NULL UNIQUE,
  occurred_at timestamptz NOT NULL
);

ALTER TABLE identity_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_challenge ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_recovery ENABLE ROW LEVEL SECURITY;
ALTER TABLE encrypted_secret_record ENABLE ROW LEVEL SECURITY;
CREATE POLICY identity_session_tenant ON identity_session USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY webauthn_credential_tenant ON webauthn_credential USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY webauthn_challenge_tenant ON webauthn_challenge USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY authorization_grant_tenant ON authorization_grant USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY identity_recovery_tenant ON identity_recovery USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY encrypted_secret_tenant ON encrypted_secret_record USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);

CREATE OR REPLACE FUNCTION identity_security_no_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'identity security audit history is append only';
END;
$$;
CREATE TRIGGER identity_security_audit_immutable BEFORE UPDATE OR DELETE ON identity_security_audit
FOR EACH ROW EXECUTE FUNCTION identity_security_no_update();
