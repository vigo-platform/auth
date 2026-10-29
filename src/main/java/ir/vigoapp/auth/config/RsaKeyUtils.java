package ir.vigoapp.auth.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;

public class RsaKeyUtils {

    public static RSAPublicKey readPublicKey(String locationOrPem) {
        try {
            String pem = resolveContent(locationOrPem);
            String cleanKey = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] decoded = Base64.getDecoder().decode(cleanKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA Public Key from: " + locationOrPem, e);
        }
    }

    public static RSAPrivateKey readPrivateKey(String locationOrPem) {
        try {
            String pem = resolveContent(locationOrPem);
            String cleanKey = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] decoded = Base64.getDecoder().decode(cleanKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA Private Key from: " + locationOrPem, e);
        }
    }

    private static String resolveContent(String locationOrPem) throws IOException {
        if (locationOrPem == null || locationOrPem.isBlank()) {
            throw new IllegalArgumentException("Key location or content cannot be empty");
        }
        if (locationOrPem.contains("-----BEGIN")) {
            return locationOrPem;
        }
        Path filePath = Paths.get(locationOrPem);
        if (Files.exists(filePath)) {
            return Files.readString(filePath, StandardCharsets.UTF_8);
        }
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource resource = loader.getResource(locationOrPem);
        if (resource.exists()) {
            try (InputStream is = resource.getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        throw new IllegalArgumentException("Could not find key file at: " + locationOrPem);
    }
}
