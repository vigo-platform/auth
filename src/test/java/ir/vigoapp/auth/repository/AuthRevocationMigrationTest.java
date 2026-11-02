package ir.vigoapp.auth.repository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Runs V3 -> V4 in an isolated schema and rolls back all fixtures and DDL. */
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DATABASE_URL", matches = ".+")
class AuthRevocationMigrationTest {
    @Test
    void migrationPreservesHistoryAndBackfillsRevokedFamilies() throws Exception {
        try (var connection = DriverManager.getConnection(System.getenv("AUTH_TEST_DATABASE_URL"),
                "postgres", System.getenv("AUTH_TEST_DATABASE_PASSWORD"))) {
            connection.setAutoCommit(false);
            try (var statement = connection.createStatement()) {
                var schema = "revocation_test_" + UUID.randomUUID().toString().replace("-", "");
                statement.execute("CREATE SCHEMA " + schema);
                statement.execute("SET LOCAL search_path TO " + schema);
                statement.execute(migration("V3__create_login_sessions.sql"));
                statement.execute("""
                        INSERT INTO auth_sessions (id, user_id, credential_version, created_at, expires_at,
                                                   revoked_at, revoked_reason)
                        VALUES ('00000000-0000-0000-0000-000000000001', 42, 3,
                                '2026-01-01Z', '2026-01-31Z', '2026-01-02Z', 'LOGOUT'),
                               ('00000000-0000-0000-0000-000000000002', 42, 3,
                                '2026-01-01Z', '2026-01-31Z', NULL, NULL);
                        INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at)
                        VALUES ('00000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000001',
                                'consumed', '2026-01-01Z', '2026-01-08Z', '2026-01-02Z'),
                               ('00000000-0000-0000-0000-000000000012', '00000000-0000-0000-0000-000000000001',
                                'unused', '2026-01-02Z', '2026-01-09Z', NULL),
                               ('00000000-0000-0000-0000-000000000013', '00000000-0000-0000-0000-000000000002',
                                'active-family', '2026-01-01Z', '2026-01-08Z', NULL);
                        """);
                statement.execute(migration("V4__add_refresh_token_revocation.sql"));
                try (var result = statement.executeQuery("""
                        SELECT s.is_revoked, s.revoked_at, s.revoked_reason,
                               t.is_revoked, t.revoked_at, t.consumed_at, t.token_hash
                        FROM refresh_tokens t JOIN auth_sessions s ON s.id = t.session_id ORDER BY t.id
                        """)) {
                    assertThat(result.next()).isTrue();
                    assertRevoked(result);
                    assertThat(result.getTimestamp(6)).isNotNull();
                    assertThat(result.getString(7)).isEqualTo("consumed");
                    assertThat(result.next()).isTrue();
                    assertRevoked(result);
                    assertThat(result.getTimestamp(6)).isNull();
                    assertThat(result.getString(7)).isEqualTo("unused");
                    assertThat(result.next()).isTrue();
                    assertThat(result.getBoolean(1)).isFalse();
                    assertThat(result.getTimestamp(2)).isNull();
                    assertThat(result.getBoolean(4)).isFalse();
                    assertThat(result.getTimestamp(5)).isNull();
                    assertThat(result.getString(7)).isEqualTo("active-family");
                    assertThat(result.next()).isFalse();
                }
            } finally {
                connection.rollback();
            }
        }
    }

    private static void assertRevoked(java.sql.ResultSet result) throws Exception {
        assertThat(result.getBoolean(1)).isTrue();
        assertThat(result.getString(3)).isEqualTo("LOGOUT");
        assertThat(result.getBoolean(4)).isTrue();
        assertThat(result.getTimestamp(5)).isEqualTo(result.getTimestamp(2));
    }

    private static String migration(String name) throws Exception {
        try (var stream = AuthRevocationMigrationTest.class.getResourceAsStream("/db/migration/" + name)) {
            if (stream == null) throw new IllegalStateException("Missing migration: " + name);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
