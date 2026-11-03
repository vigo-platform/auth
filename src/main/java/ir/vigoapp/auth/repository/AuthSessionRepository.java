package ir.vigoapp.auth.repository;

import ir.vigoapp.auth.entity.AuthSession;
import jakarta.persistence.LockModeType;
import jakarta.persistence.QueryHint;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository extends JpaRepository<AuthSession, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(@QueryHint(name = "jakarta.persistence.lock.timeout", value = "3000"))
    Optional<AuthSession> findLockedById(UUID id);

    @Modifying(flushAutomatically = true)
    @Query("update AuthSession s set s.revoked = true, s.revokedAt = coalesce(s.revokedAt, :now), "
            + "s.revokedReason = coalesce(s.revokedReason, :reason) "
            + "where s.userId = :userId and (s.revoked = false or s.revokedAt is null)")
    int revokeAllByUserId(@Param("userId") long userId, @Param("now") Instant now, @Param("reason") String reason);

    @Modifying(flushAutomatically = true)
    @Query("update AuthSession s set s.revoked = true, s.revokedAt = coalesce(s.revokedAt, :now), "
            + "s.revokedReason = coalesce(s.revokedReason, :reason) "
            + "where s.userId = :userId and s.credentialVersion < :credentialVersion "
            + "and (s.revoked = false or s.revokedAt is null)")
    int revokeOlderCredentialsByUserId(@Param("userId") long userId, @Param("credentialVersion") long credentialVersion,
                                      @Param("now") Instant now, @Param("reason") String reason);

    @Modifying
    @Query("update AuthSession s set s.revoked = true, s.revokedAt = coalesce(s.revokedAt, :now), "
            + "s.revokedReason = coalesce(s.revokedReason, 'EXPIRED_CLEANUP') "
            + "where s.expiresAt < :cutoff and (s.revoked = false or s.revokedAt is null)")
    int revokeExpiredBefore(@Param("cutoff") Instant cutoff, @Param("now") Instant now);
}
