package com.lisovskyi.security.autoconfigure.security.jwt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Generates and hashes cryptographically secure opaque tokens
 * suitable for use as refresh tokens.
 *
 * <p>Unlike JWT, an opaque token is a random string with no embedded claims.
 * The raw token is returned to the client; only its {@link #hash(String) SHA-256 hash}
 * is stored in the database. This means a leaked database does not expose
 * valid tokens, and a leaked token cannot be used to forge another one.
 *
 * <p>Typical usage in an auth service:
 * <pre>{@code
 * String raw  = opaqueTokenService.generate(); // send to client
 * String hash = opaqueTokenService.hash(raw);  // store in DB
 * }</pre>
 *
 * <p>To verify an incoming refresh token:
 * <pre>{@code
 * String hash = opaqueTokenService.hash(incomingToken);
 * RefreshToken stored = repo.findByTokenHash(hash)
 *         .orElseThrow(...);
 * }</pre>
 */
public class OpaqueTokenService {

    private static final int TOKEN_BYTES = 32; // 256 bits
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a cryptographically secure opaque token.
     *
     * <p>Produces {@value TOKEN_BYTES} random bytes encoded as a Base64URL
     * string without padding — safe to use in HTTP headers and cookies.
     *
     * @return a random Base64URL-encoded token string
     */
    public String generate() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Computes the SHA-256 hash of a token for secure storage.
     *
     * <p>Only the hash should ever be persisted — never the raw token itself.
     *
     * @param token the raw opaque token received from the client
     * @return lowercase hex-encoded SHA-256 digest of the token
     */
    public String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
