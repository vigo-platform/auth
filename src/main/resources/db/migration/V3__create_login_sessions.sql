CREATE TABLE auth_sessions
(
    id                 UUID PRIMARY KEY,
    user_id            BIGINT NOT NULL CHECK (user_id > 0),
    credential_version BIGINT NOT NULL CHECK (credential_version > 0),
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at         TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at         TIMESTAMP WITH TIME ZONE,
    revoked_reason     VARCHAR(32),
    ip_address         VARCHAR(64),
    user_agent         VARCHAR(512),
    device_id          VARCHAR(128),
    CONSTRAINT ck_session_expiry CHECK (expires_at > created_at)
);
CREATE INDEX ix_auth_sessions_user ON auth_sessions (user_id);
CREATE INDEX ix_auth_sessions_expiry ON auth_sessions (expires_at);

CREATE TABLE refresh_tokens
(
    id          UUID PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES auth_sessions (id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT ck_refresh_token_expiry CHECK (expires_at > created_at)
);
CREATE INDEX ix_refresh_tokens_session ON refresh_tokens (session_id);
