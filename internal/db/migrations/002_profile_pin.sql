-- Profile, PIN (bcrypt hash + lockout counters), account numbers, transfer notes.
ALTER TABLE users
    ADD COLUMN full_name           TEXT,
    ADD COLUMN handle              TEXT,
    ADD COLUMN phone               TEXT,
    ADD COLUMN pin_hash            TEXT,
    ADD COLUMN pin_failed_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN pin_locked_until    TIMESTAMPTZ;

ALTER TABLE users ADD CONSTRAINT users_handle_key UNIQUE (handle);
ALTER TABLE users ADD CONSTRAINT users_handle_format CHECK (handle IS NULL OR handle ~ '^[a-z0-9_]{3,16}$');
ALTER TABLE users ADD CONSTRAINT users_phone_format CHECK (phone IS NULL OR phone ~ '^[0-9]{10}$');

ALTER TABLE accounts ADD COLUMN account_number TEXT UNIQUE;
UPDATE accounts SET account_number = lpad((floor(random() * 9e9) + 1e9)::bigint::text, 10, '0') WHERE account_number IS NULL;
ALTER TABLE accounts ALTER COLUMN account_number SET NOT NULL;
ALTER TABLE accounts ALTER COLUMN currency SET DEFAULT 'INR';

ALTER TABLE transactions ADD COLUMN note TEXT NOT NULL DEFAULT '';
