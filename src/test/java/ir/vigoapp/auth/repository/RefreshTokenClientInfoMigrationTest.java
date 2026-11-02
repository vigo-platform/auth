package ir.vigoapp.auth.repository;

import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Runs V3 -> V5 in an isolated schema and rolls back all fixtures and DDL. */
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DATABASE_URL", matches = ".+")
class RefreshTokenClientInfoMigrationTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void movesOnlyLatestKnownMetadataAndPreservesTokenHistory(boolean sameIssuanceTime) throws Exception {
        try (var connection = DriverManager.getConnection(System.getenv("AUTH_TEST_DATABASE_URL"),
                "postgres", System.getenv("AUTH_TEST_DATABASE_PASSWORD"))) {
            connection.setAutoCommit(false);
            try (var statement = connection.createStatement()) {
                var schema = "token_client_test_" + UUID.randomUUID().toString().replace("-", "");
                statement.execute("CREATE SCHEMA " + schema);
                statement.execute("SET LOCAL search_path TO " + schema);
                statement.execute(migration("V3__create_login_sessions.sql"));
                statement.execute("""
                        INSERT INTO auth_sessions (id, user_id, credential_version, created_at, expires_at,
                                                   revoked_at, revoked_reason, ip_address, user_agent, device_id)
                        VALUES ('00000000-0000-0000-0000-000000000001', 42, 3,
                                '2026-01-01Z', '2026-01-31Z', NULL, NULL,
                                '203.0.113.1', 'initial-browser', 'initial-device'),
                               ('00000000-0000-0000-0000-000000000002', 42, 3,
                                '2026-01-01Z', '2026-01-31Z', '2026-01-03Z', 'LOGOUT',
                                '2001:db8::1', 'latest-browser', 'latest-device'),
                               ('00000000-0000-0000-0000-000000000003', 43, 1,
                                '2026-01-01Z', '2026-01-31Z', NULL, NULL, NULL, NULL, NULL);
                        INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at)
                        VALUES ('00000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000001',
                                'initial', '2026-01-01Z', '2026-01-08Z', NULL),
                               ('00000000-0000-0000-0000-000000000022', '00000000-0000-0000-0000-000000000002',
                                'consumed', '2026-01-01Z', '2026-01-08Z', '2026-01-02Z'),
                               ('00000000-0000-0000-0000-000000000021', '00000000-0000-0000-0000-000000000002',
                                'latest', '2026-01-02Z', '2026-01-09Z', NULL),
                               ('00000000-0000-0000-0000-000000000031', '00000000-0000-0000-0000-000000000003',
                                'no-metadata', '2026-01-01Z', '2026-01-08Z', NULL);
                        """);
                if (sameIssuanceTime) {
                    statement.execute("UPDATE refresh_tokens SET created_at = '2026-01-01Z' WHERE token_hash = 'latest'");
                }
                statement.execute(migration("V4__add_refresh_token_revocation.sql"));
                var history = history(connection);
                statement.execute(migration("V5__move_client_info_to_refresh_tokens.sql"));

                assertThat(history(connection)).containsExactlyElementsOf(history);
                try (var result = statement.executeQuery("""
                        SELECT token_hash, ip_address, user_agent, device_id
                        FROM refresh_tokens ORDER BY token_hash
                        """)) {
                    assertThat(result.next()).isTrue();
                    assertThat(result.getString(1)).isEqualTo("consumed");
                    assertThat(result.getString(2)).isNull();
                    assertThat(result.getString(3)).isNull();
                    assertThat(result.getString(4)).isNull();
                    assertThat(result.next()).isTrue();
                    assertThat(result.getString(1)).isEqualTo("initial");
                    assertThat(result.getString(2)).isEqualTo("203.0.113.1");
                    assertThat(result.getString(3)).isEqualTo("initial-browser");
                    assertThat(result.getString(4)).isEqualTo("initial-device");
                    assertThat(result.next()).isTrue();
                    assertThat(result.getString(1)).isEqualTo("latest");
                    assertThat(result.getString(2)).isEqualTo("2001:db8::1");
                    assertThat(result.getString(3)).isEqualTo("latest-browser");
                    assertThat(result.getString(4)).isEqualTo("latest-device");
                    assertThat(result.next()).isTrue();
                    assertThat(result.getString(1)).isEqualTo("no-metadata");
                    assertThat(result.getString(2)).isNull();
                    assertThat(result.getString(3)).isNull();
                    assertThat(result.getString(4)).isNull();
                    assertThat(result.next()).isFalse();
                }
                try (var result = statement.executeQuery("""
                        SELECT column_name FROM information_schema.columns
                        WHERE table_schema = current_schema() AND table_name = 'auth_sessions'
                          AND column_name IN ('ip_address', 'user_agent', 'device_id')
                        """)) {
                    assertThat(result.next()).isFalse();
                }
            } finally {
                connection.rollback();
            }
        }
    }

    private static List<String> history(Connection connection) throws Exception {
        try (var statement = connection.createStatement(); var result = statement.executeQuery("""
                SELECT s.id, s.user_id, s.credential_version, s.created_at, s.expires_at,
                       s.is_revoked, s.revoked_at, s.revoked_reason,
                       t.id, t.session_id, t.token_hash, t.created_at, t.expires_at,
                       t.consumed_at, t.is_revoked, t.revoked_at
                FROM auth_sessions s JOIN refresh_tokens t ON t.session_id = s.id ORDER BY t.id
                """)) {
            var values = new ArrayList<String>();
            while (result.next()) {
                for (int i = 1; i <= result.getMetaData().getColumnCount(); i++) values.add(result.getString(i));
            }
            return values;
        }
    }

    private static String migration(String name) throws Exception {
        try (var stream = RefreshTokenClientInfoMigrationTest.class.getResourceAsStream("/db/migration/" + name)) {
            if (stream == null) throw new IllegalStateException("Missing migration: " + name);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
