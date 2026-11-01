package ir.vigoapp.auth.repository;

import ir.vigoapp.auth.entity.AuthSetting;
import org.hibernate.cfg.Configuration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;

import java.sql.DriverManager;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests only advisory locks in a disposable PostgreSQL database; no tables or migrations are needed. */
@EnabledIfEnvironmentVariable(named = "AUTH_LOCK_TEST_URL", matches = ".+")
class AuthSettingRepositoryLockTest {

    @Test
    void voidQueryAcquiresLockUntilCommit() throws Exception {
        verifyLockRelease(true);
    }

    @Test
    void voidQueryAcquiresLockUntilRollback() throws Exception {
        verifyLockRelease(false);
    }

    private void verifyLockRelease(boolean commit) throws Exception {
        var url = System.getenv("AUTH_LOCK_TEST_URL");
        var password = System.getenv("AUTH_LOCK_TEST_PASSWORD");
        try (var factory = new Configuration()
                .addAnnotatedClass(AuthSetting.class)
                .setProperty("hibernate.connection.url", url)
                .setProperty("hibernate.connection.username", "postgres")
                .setProperty("hibernate.connection.password", password)
                .setProperty("hibernate.hbm2ddl.auto", "none")
                .buildSessionFactory();
             var entityManager = factory.createEntityManager();
             var contender = DriverManager.getConnection(url, "postgres", password)) {
            contender.setAutoCommit(false);
            var repository = new JpaRepositoryFactory(entityManager).getRepository(AuthSettingRepository.class);
            var transaction = entityManager.getTransaction();
            transaction.begin();
            try {
                repository.lockForRevisionChange();
                try (var query = contender.createStatement();
                     var result = query.executeQuery("SELECT pg_try_advisory_xact_lock(12234, 1)")) {
                    assertThat(result.next()).isTrue();
                    assertThat(result.getBoolean(1)).isFalse();
                }
                if (commit) {
                    transaction.commit();
                } else {
                    transaction.rollback();
                }
                try (var query = contender.createStatement();
                     var result = query.executeQuery("SELECT pg_try_advisory_xact_lock(12234, 1)")) {
                    assertThat(result.next()).isTrue();
                    assertThat(result.getBoolean(1)).isTrue();
                }
            } finally {
                if (transaction.isActive()) {
                    transaction.rollback();
                }
                contender.rollback();
            }
        }
    }
}
