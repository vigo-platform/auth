package ir.vigoapp.auth.repository;

import ir.vigoapp.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    // Read only the ID first: do not put a stale session/token entity in the persistence context before locking.
    @Query("select t.session.id from RefreshToken t where t.tokenHash = :hash")
    Optional<UUID> findSessionIdByTokenHash(@Param("hash") String hash);

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.active = false, t.revokedAt = coalesce(t.revokedAt, :now) "
            + "where (t.active = true or t.revokedAt is null) "
            + "and t.session.id in (select s.id from AuthSession s where s.expiresAt < :cutoff)")
    int revokeForExpiredSessionsBefore(@Param("cutoff") Instant cutoff, @Param("now") Instant now);

    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.active = false, t.revokedAt = coalesce(t.revokedAt, :now) "
            + "where t.session.id = :sessionId and (t.active = true or t.revokedAt is null)")
    int revokeAllBySessionId(@Param("sessionId") UUID sessionId, @Param("now") Instant now);

    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.active = false, t.revokedAt = coalesce(t.revokedAt, :now) "
            + "where (t.active = true or t.revokedAt is null) "
            + "and t.session.id in (select s.id from AuthSession s where s.userId = :userId)")
    int revokeAllByUserId(@Param("userId") long userId, @Param("now") Instant now);

    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.active = false, t.revokedAt = coalesce(t.revokedAt, :now) "
            + "where (t.active = true or t.revokedAt is null) "
            + "and t.session.id in (select s.id from AuthSession s "
            + "where s.userId = :userId and s.credentialVersion < :credentialVersion)")
    int revokeOlderCredentialsByUserId(@Param("userId") long userId, @Param("credentialVersion") long credentialVersion,
                                      @Param("now") Instant now);

    // Synchronize stored state even when an expired token is never presented again.
    // Consumption/expiry are not revocations: preserve the audit timestamps as they are.
    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.active = false where t.active = true and "
            + "(t.consumedAt is not null or t.revokedAt is not null or t.expiresAt <= :now "
            + "or t.session.id in (select s.id from AuthSession s "
            + "where s.revoked = true or s.revokedAt is not null or s.expiresAt <= :now))")
    int deactivateUnusable(@Param("now") Instant now);
}
