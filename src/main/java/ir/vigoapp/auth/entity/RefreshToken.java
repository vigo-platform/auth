package ir.vigoapp.auth.entity;

import ir.vigoapp.auth.dto.ClientInfo;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens", uniqueConstraints = @UniqueConstraint(name = "uk_refresh_token_hash", columnNames = "token_hash"))
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "session_id", nullable = false, updatable = false)
    private AuthSession session;
    @Column(name = "token_hash", nullable = false, updatable = false, length = 64)
    private String tokenHash;
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
    @Column(nullable = false, updatable = false)
    private Instant expiresAt;
    @Column(length = 64, updatable = false)
    private String ipAddress;
    @Column(length = 512, updatable = false)
    private String userAgent;
    @Column(length = 128, updatable = false)
    private String deviceId;
    private Instant consumedAt;
    @Column(name = "is_active", nullable = false)
    private boolean active;
    private Instant revokedAt;

    public RefreshToken(AuthSession session, String tokenHash, Instant now, Instant expiresAt, ClientInfo client) {
        this.session = session;
        this.tokenHash = tokenHash;
        this.createdAt = now;
        this.expiresAt = expiresAt;
        this.ipAddress = client.ipAddress();
        this.userAgent = client.userAgent();
        this.deviceId = client.deviceId();
        this.active = expiresAt.isAfter(now) && session.isActive(now);
    }

    public void consume(Instant now) {
        active = false;
        if (consumedAt == null) consumedAt = now;
    }

    public void revoke(Instant now) {
        active = false;
        if (revokedAt == null) revokedAt = now;
    }

    public boolean isUsable(Instant now) {
        return active && revokedAt == null && consumedAt == null
                && expiresAt.isAfter(now) && session.isActive(now);
    }
}
