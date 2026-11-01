package ir.vigoapp.auth.repository;

import ir.vigoapp.auth.entity.AuthSetting;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

/**
 * Persists the application-wide auth settings.
 *
 * @version 1.0.0
 * @author logTAHA
 */
public interface AuthSettingRepository extends JpaRepository<AuthSetting, Long> {

    Optional<AuthSetting> findFirstByOrderByVersionDescIdDesc();

    @Query(value = "SELECT pg_advisory_xact_lock(12234, 1)", nativeQuery = true)
    void lockForRevisionChange();
}
