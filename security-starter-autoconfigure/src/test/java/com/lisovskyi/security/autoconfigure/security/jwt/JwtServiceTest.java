package com.lisovskyi.security.autoconfigure.security.jwt;

import com.lisovskyi.security.autoconfigure.security.SecurityPrincipal;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers the key-rotation path specifically: a token signed with what USED to be the
 * current key must still validate once that key becomes "previous" and a new key takes
 * over signing. This is exactly the scenario a real rotation goes through and isn't
 * exercised by anything else - unit or app-level - so it lives here, next to JwtService.
 */
class JwtServiceTest {

    private static String keyA;
    private static String keyB;

    @BeforeAll
    static void generateKeys() throws Exception {
        keyA = generateBase64PrivateKey();
        keyB = generateBase64PrivateKey();
    }

    private static String generateBase64PrivateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
    }

    private JwtProperties propertiesFor(String privateKey, String previousPrivateKey) {
        JwtProperties props = new JwtProperties();
        props.setPrivateKey(privateKey);
        props.setPreviousPrivateKey(previousPrivateKey);
        props.setIssuer("rotation-test");
        props.setAccessTokenExpiration(900_000L);
        return props;
    }

    private SecurityPrincipal testPrincipal() {
        return new SecurityPrincipal() {
            @Override
            public Long getId() {
                return 1L;
            }

            @Override
            public String getRole() {
                return "USER";
            }

            @Override
            public String getPassword() {
                return null;
            }

            @Override
            public String getUsername() {
                return "user@sentio.dev";
            }
        };
    }

    @Test
    void rotation_tokenSignedWithFormerCurrentKey_isAcceptedOnceItBecomesPrevious() {
        // Before rotation: keyA is the only active key.
        JwtService before = new JwtService(propertiesFor(keyA, null));
        String tokenFromOldKey = before.generateToken(testPrincipal(), Map.of());

        // After rotation: keyB signs new tokens, keyA is kept only for verifying old ones.
        JwtService after = new JwtService(propertiesFor(keyB, keyA));

        assertThat(after.isTokenValid(tokenFromOldKey)).isTrue();
    }

    @Test
    void rotation_tokensFromTheNewCurrentKey_areAlsoAccepted() {
        JwtService after = new JwtService(propertiesFor(keyB, keyA));
        String tokenFromNewKey = after.generateToken(testPrincipal(), Map.of());

        assertThat(after.isTokenValid(tokenFromNewKey)).isTrue();
    }

    @Test
    void withoutRotationConfigured_tokenFromAnUnrelatedKeyIsRejected() {
        JwtService serviceA = new JwtService(propertiesFor(keyA, null));
        String tokenFromA = serviceA.generateToken(testPrincipal(), Map.of());

        // serviceB was never told about keyA (no previous-key configured) - must reject.
        JwtService serviceB = new JwtService(propertiesFor(keyB, null));

        assertThat(serviceB.isTokenValid(tokenFromA)).isFalse();
    }

    // ---- previous-private-key edge cases -------------------------------
    //
    // A blank previous-private-key is not a hypothetical: Doppler/k8s secret
    // templating can easily produce an empty string instead of an absent key
    // when a rotation isn't in progress. That must not be treated as "a
    // previous key is configured" - the constructor should just ignore it,
    // not try to decode zero bytes as an RSA key and blow up bean creation.

    @Test
    void nullPreviousPrivateKey_isTreatedAsNotConfigured() {
        JwtService service = new JwtService(propertiesFor(keyA, null));

        assertThat(service.getPreviousPublicKey()).isNull();
        assertThat(service.getPreviousKeyId()).isNull();
    }

    @Test
    void emptyPreviousPrivateKey_isTreatedAsNotConfigured() {
        JwtService service = new JwtService(propertiesFor(keyA, ""));

        assertThat(service.getPreviousPublicKey()).isNull();
        assertThat(service.getPreviousKeyId()).isNull();
    }

    @Test
    void blankPreviousPrivateKey_isTreatedAsNotConfigured() {
        JwtService service = new JwtService(propertiesFor(keyA, "   "));

        assertThat(service.getPreviousPublicKey()).isNull();
        assertThat(service.getPreviousKeyId()).isNull();
    }

    @Test
    void presentPreviousPrivateKey_isActuallyDecodedAndExposed() {
        JwtService service = new JwtService(propertiesFor(keyB, keyA));

        assertThat(service.getPreviousPublicKey()).isNotNull();
        assertThat(service.getPreviousKeyId())
                .isNotNull()
                .isNotEqualTo(service.getKeyId());
    }
}
