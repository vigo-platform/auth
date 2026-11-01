ALTER TABLE auth_settings
    ADD updated_at TIMESTAMP WITHOUT TIME ZONE;

ALTER TABLE auth_settings
    ALTER COLUMN updated_at SET NOT NULL;