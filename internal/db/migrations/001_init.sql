CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Money is stored as integer minor units (e.g. cents). Never floats.
CREATE TABLE accounts (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id),
    currency   CHAR(3) NOT NULL DEFAULT 'USD',
    balance    BIGINT NOT NULL DEFAULT 0 CHECK (balance >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_accounts_user ON accounts(user_id);

CREATE TABLE transactions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id              UUID NOT NULL REFERENCES accounts(id),
    type                    TEXT NOT NULL CHECK (type IN ('deposit','withdrawal','transfer_in','transfer_out')),
    amount                  BIGINT NOT NULL CHECK (amount > 0),
    balance_after           BIGINT NOT NULL,
    counterparty_account_id UUID REFERENCES accounts(id),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_transactions_account ON transactions(account_id, created_at DESC, id DESC);
