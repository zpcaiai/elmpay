-- B34: distinguish void from partial-capture close for durable recovery.
ALTER TABLE payment_attempt
    DROP CONSTRAINT IF EXISTS payment_attempt_operation_check;

ALTER TABLE payment_attempt
    ADD CONSTRAINT payment_attempt_operation_check
    CHECK (operation IN ('payment', 'capture', 'cancel', 'close', 'query'));
