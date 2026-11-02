package ir.vigoapp.auth.repository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Upgrade a populated V5 schema without deleting history or reactivating unusable tokens. */
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DATABASE_URL", matches = ".+")
class RefreshTokenActiveMigrationTest {
    @Test
    void backfillsActivityFromAllTokenAndSessionSignalsAndPreservesHistory() throws Exception {
        try (var connection = DriverManager.getConnection(System.getenv("AUTH_TEST_DATABASE_URL"),
                "postgres", System.getenv("AUTH_TEST_DATABASE_PASSWORD"))) {
            connection.setAutoCommit(false);
            try (var statement = connection.createStatement()) {
                String schema = "active_test_" + UUID.randomUUID().toString().replace("-", "");
                statement.execute("CREATE SCHEMA " + schema);
                statement.execute("SET LOCAL search_path TO " + schema);
                for (var migration : List.of("V3__create_login_sessions.sql", "V4__add_refresh_token_revocation.sql",
                        "V5__move_client_info_to_refresh_tokens.sql")) {
                    statement.execute(migration(migration));
                }
                String cases = "(VALUES ('active'), ('consumed'), ('token-flag'), ('token-timestamp'), "
                        + "('token-expired'), ('session-flag'), ('session-timestamp'), ('session-expired')) AS c(label)";
                statement.execute("""
                        INSERT INTO auth_sessions
                            (id, user_id, credential_version, created_at, expires_at, is_revoked, revoked_at, revoked_reason)
                        SELECT md5(label)::uuid, 42, 3, CURRENT_TIMESTAMP - INTERVAL '2 days',
                            CASE WHEN label = 'session-expired' THEN CURRENT_TIMESTAMP - INTERVAL '1 day'
                                 ELSE CURRENT_TIMESTAMP + INTERVAL '30 days' END,
                            label = 'session-flag',
                            CASE WHEN label = 'session-timestamp' THEN CURRENT_TIMESTAMP - INTERVAL '1 hour' END,
                            CASE WHEN label = 'session-flag' THEN 'LOGOUT' END
                        FROM
                        """ + cases);
                statement.execute("""
                        INSERT INTO refresh_tokens
                            (id, session_id, token_hash, created_at, expires_at, consumed_at, is_revoked,
                             revoked_at, ip_address, user_agent, device_id)
                        SELECT md5('token-' || label)::uuid, md5(label)::uuid, label,
                            CURRENT_TIMESTAMP - INTERVAL '2 days',
                            CASE WHEN label = 'token-expired' THEN CURRENT_TIMESTAMP - INTERVAL '1 day'
                                 ELSE CURRENT_TIMESTAMP + INTERVAL '7 days' END,
                            CASE WHEN label = 'consumed' THEN CURRENT_TIMESTAMP - INTERVAL '1 hour' END,
                            label = 'token-flag',
                            CASE WHEN label = 'token-timestamp' THEN CURRENT_TIMESTAMP - INTERVAL '1 hour' END,
                            '127.0.0.1', 'migration-test', 'test-device'
                        FROM
                        """ + cases);
                var history = history(connection);

                statement.execute(migration("V6__replace_refresh_token_revoked_with_active.sql"));

                assertThat(history(connection)).containsExactlyElementsOf(history);
                try (var rows = statement.executeQuery("SELECT token_hash, is_active FROM refresh_tokens ORDER BY token_hash")) {
                    int count = 0;
                    while (rows.next()) {
                        assertThat(rows.getBoolean("is_active")).isEqualTo(rows.getString("token_hash").equals("active"));
                        count++;
                    }
                    assertThat(count).isEqualTo(8);
                }
                try (var columns = statement.executeQuery("""
                        SELECT column_name FROM information_schema.columns
                        WHERE table_schema = current_schema() AND table_name = 'refresh_tokens'
                          AND column_name = 'is_revoked'
                        """)) {
                    assertThat(columns.next()).isFalse();
                }
                // Direct inserts without an explicit activity decision remain inactive by default.
                statement.execute("""
                        INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at)
                        VALUES (md5('default')::uuid, md5('active')::uuid, 'default',
                                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 day')
                        """);
                try (var row = statement.executeQuery("SELECT is_active FROM refresh_tokens WHERE token_hash = 'default'")) {
                    assertThat(row.next()).isTrue();
                    assertThat(row.getBoolean(1)).isFalse();
                }
            } finally {
                connection.rollback();
            }
        }
    }

    private static List<String> history(Connection connection) throws Exception {
        try (var statement = connection.createStatement(); var rows = statement.executeQuery("""
                SELECT s.*, t.id, t.session_id, t.token_hash, t.created_at, t.expires_at, t.consumed_at,
                       t.revoked_at, t.ip_address, t.user_agent, t.device_id
                FROM auth_sessions s JOIN refresh_tokens t ON t.session_id = s.id ORDER BY t.token_hash
                """)) {
            var values = new ArrayList<String>();
            while (rows.next()) {
                for (int i = 1; i <= rows.getMetaData().getColumnCount(); i++) values.add(rows.getString(i));
            }
            return values;
        }
    }

    private static String migration(String name) throws Exception {
        try (var stream = RefreshTokenActiveMigrationTest.class.getResourceAsStream("/db/migration/" + name)) {
            if (stream == null) throw new IllegalStateException("Missing migration: " + name);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
