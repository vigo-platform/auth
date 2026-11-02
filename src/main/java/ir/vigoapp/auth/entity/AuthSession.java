package ir.vigoapp.auth.entity;

import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.service.login.ClientInfo;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_sessions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthSession {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(nullable = false, updatable = false)
    private long userId;
    @Column(nullable = false, updatable = false)
    private long credentialVersion;
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
    @Column(nullable = false, updatable = false)
    private Instant expiresAt;
    @Column(name = "is_revoked", nullable = false)
    private boolean revoked;
    private Instant revokedAt;
    @Column(length = 32)
    private String revokedReason;
    @Column(length = 64)
    private String ipAddress;
    @Column(length = 512)
    private String userAgent;
    @Column(length = 128)
    private String deviceId;

    public AuthSession(UserAccount user, Instant now, Instant expiresAt, ClientInfo client) {
        this.userId = user.userId();
        this.credentialVersion = user.credentialVersion();
        this.createdAt = now;
        this.expiresAt = expiresAt;
        updateClient(client);
    }

    public void updateClient(ClientInfo client) {
        this.ipAddress = client.ipAddress();
        this.userAgent = client.userAgent();
        this.deviceId = client.deviceId();
    }

    public boolean isActive(Instant now) {
        return !revoked && revokedAt == null && expiresAt.isAfter(now);
    }

    public void revoke(Instant now, String reason) {
        revoked = true;
        if (revokedAt == null) {
            revokedAt = now;
        }
        if (revokedReason == null) revokedReason = reason;
    }
}
