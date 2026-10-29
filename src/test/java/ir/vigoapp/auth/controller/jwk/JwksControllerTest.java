package ir.vigoapp.auth.controller.jwk;

import com.nimbusds.jose.jwk.RSAKey;
import ir.vigoapp.auth.config.RsaKeyUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class JwksControllerTest {

    private MockMvc mockMvc;
    private RSAKey rsaKey;

    @BeforeEach
    void setUp() {
        RSAPublicKey publicKey = RsaKeyUtils.readPublicKey(".keys/public_key.pem");
        RSAPrivateKey privateKey = RsaKeyUtils.readPrivateKey(".keys/private_key.pem");

        rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("vigo-auth-key-1")
                .build();

        JwksController controller = new JwksController(rsaKey);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @DisplayName("GET /.well-known/jwks.json should return public keys and NOT private key parameters")
    void shouldReturnPublicJwks() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys", hasSize(1)))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value("vigo-auth-key-1"))
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist());
    }
}
