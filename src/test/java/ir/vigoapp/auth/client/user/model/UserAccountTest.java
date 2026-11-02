package ir.vigoapp.auth.client.user.model;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UserAccountTest {
    @Test
    void builderKeepsRolesImmutableAndIndependentOfTheInputList() {
        var roles = new ArrayList<>(List.of("USER"));
        var account = UserAccount.builder().userId(42).roles(roles).build();

        roles.add("ADMIN");

        assertThat(account.roles()).containsExactly("USER");
        assertThatThrownBy(() -> account.roles().add("ADMIN"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void toBuilderPreservesTheAccountSnapshotWhenChangingTwoFactorSettings() {
        var original = UserAccount.builder()
                .userId(42)
                .roles(List.of("USER"))
                .email("user@example.com")
                .phone("+989123456789")
                .status(UserAccount.AccountStatus.ACTIVE)
                .emailVerified(true)
                .phoneVerified(true)
                .credentialVersion(3)
                .credentialsExpired(false)
                .twoFactorEnabled(false)
                .build();

        var updated = original.toBuilder().twoFactorEnabled(true).build();

        assertThat(original.twoFactorEnabled()).isFalse();
        assertThat(updated.twoFactorEnabled()).isTrue();
        assertThat(updated).usingRecursiveComparison()
                .ignoringFields("twoFactorEnabled").isEqualTo(original);
    }
}
