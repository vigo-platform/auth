ALTER TABLE refresh_tokens ADD COLUMN revoked_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE auth_sessions ADD COLUMN is_revoked BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE refresh_tokens ADD COLUMN is_revoked BOOLEAN NOT NULL DEFAULT FALSE;

-- Preserve the revocation state of existing sessions and their complete token families.
UPDATE auth_sessions SET is_revoked = TRUE WHERE revoked_at IS NOT NULL;

UPDATE refresh_tokens t
SET is_revoked = TRUE, revoked_at = s.revoked_at
FROM auth_sessions s
WHERE t.session_id = s.id AND s.is_revoked = TRUE;
