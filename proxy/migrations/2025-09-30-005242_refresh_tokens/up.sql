CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE,
    owner_principal TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX refresh_tokens_owner_principal_idx ON refresh_tokens (owner_principal);
CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);
