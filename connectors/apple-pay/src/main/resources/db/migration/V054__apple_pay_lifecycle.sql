CREATE TABLE apple_pay_domain (
    tenant_id VARCHAR(64) NOT NULL,
    merchant_account_id VARCHAR(64) NOT NULL,
    domain_name VARCHAR(253) NOT NULL,
    association_sha256 CHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('PENDING', 'VERIFIED', 'REVOKED')),
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, merchant_account_id, domain_name)
);

CREATE TABLE apple_pay_certificate (
    tenant_id VARCHAR(64) NOT NULL,
    merchant_account_id VARCHAR(64) NOT NULL,
    certificate_version VARCHAR(64) NOT NULL,
    private_key_ref VARCHAR(320) NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'OVERLAP', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, merchant_account_id, certificate_version),
    CHECK (valid_until > valid_from),
    CHECK (private_key_ref ~ '^(kms|hsm|vault)://')
);

CREATE INDEX apple_pay_certificate_active_idx
    ON apple_pay_certificate (tenant_id, merchant_account_id, valid_until)
    WHERE status IN ('ACTIVE', 'OVERLAP');

CREATE TABLE apple_pay_merchant_token (
    tenant_id VARCHAR(64) NOT NULL,
    merchant_account_id VARCHAR(64) NOT NULL,
    token_reference_hash CHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, merchant_account_id, token_reference_hash)
);

-- Production migration runners must apply tenant RLS policies using their deployment role.
