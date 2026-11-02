-- Preserve token history while making activity a positive, fail-closed state.
ALTER TABLE refresh_tokens RENAME COLUMN is_revoked TO is_active;
ALTER TABLE refresh_tokens ALTER COLUMN is_active SET DEFAULT FALSE;

-- is_active still contains the former is_revoked value during this conversion.
UPDATE refresh_tokens t
SET is_active = (
    NOT t.is_active
    AND t.revoked_at IS NULL
    AND t.consumed_at IS NULL
    AND t.expires_at > CURRENT_TIMESTAMP
    AND EXISTS (
        SELECT 1 FROM auth_sessions s
        WHERE s.id = t.session_id
          AND s.is_revoked = FALSE
          AND s.revoked_at IS NULL
          AND s.expires_at > CURRENT_TIMESTAMP
    )
);

CREATE INDEX ix_refresh_tokens_active_expiry ON refresh_tokens (expires_at) WHERE is_active = TRUE;
