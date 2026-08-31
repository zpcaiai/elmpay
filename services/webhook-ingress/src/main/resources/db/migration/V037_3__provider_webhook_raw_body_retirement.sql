-- Retire legacy provider payload storage after V037_1 has quarantined every row that was
-- accepted without a durable verification digest.  The live inbox retains only the digest and
-- canonical, bounded effect facts; raw provider bodies must never remain queryable.
ALTER TABLE provider_webhook_inbox
    DROP COLUMN raw_body;

-- Rollback: restore the legacy raw_body BYTEA column only during a controlled migration rollback.
