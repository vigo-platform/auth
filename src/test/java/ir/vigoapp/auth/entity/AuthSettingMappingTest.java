package ir.vigoapp.auth.entity;

import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.boot.spi.MetadataImplementor;
import org.junit.jupiter.api.Test;

class AuthSettingMappingTest {

    @Test
    void hibernateAcceptsEntityMappingWithoutConnectingToDatabase() {
        var registry = new StandardServiceRegistryBuilder()
                .applySetting("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect")
                .applySetting("hibernate.boot.allow_jdbc_metadata_access", false)
                .build();
        try {
            var metadata = (MetadataImplementor) new MetadataSources(registry)
                    .addAnnotatedClass(AuthSetting.class)
                    .buildMetadata();
            metadata.validate();
        } finally {
            StandardServiceRegistryBuilder.destroy(registry);
        }
    }
}
