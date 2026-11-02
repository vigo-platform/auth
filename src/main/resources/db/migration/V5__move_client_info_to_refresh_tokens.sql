ALTER TABLE refresh_tokens ADD COLUMN ip_address VARCHAR(64);
ALTER TABLE refresh_tokens ADD COLUMN user_agent VARCHAR(512);
ALTER TABLE refresh_tokens ADD COLUMN device_id VARCHAR(128);

-- Sessions hold only the last issuance's client info; earlier token metadata is unknown.
-- Prefer the unconsumed successor when issuance timestamps are equal.
UPDATE refresh_tokens t
SET ip_address = s.ip_address, user_agent = s.user_agent, device_id = s.device_id
FROM auth_sessions s,
     (SELECT DISTINCT ON (session_id) id, session_id
      FROM refresh_tokens
      ORDER BY session_id, created_at DESC, consumed_at DESC NULLS FIRST, id DESC) latest
WHERE t.id = latest.id AND s.id = latest.session_id;

ALTER TABLE auth_sessions DROP COLUMN ip_address;
ALTER TABLE auth_sessions DROP COLUMN user_agent;
ALTER TABLE auth_sessions DROP COLUMN device_id;
