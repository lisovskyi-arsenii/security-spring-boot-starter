package com.lisovskyi.security.autoconfigure.security.jwt;

import com.lisovskyi.security.autoconfigure.security.SecurityPrincipal;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Jwks;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
public class JwtService {

    private static final String KEY_FACTORY_ALGORITHM = "RSA";

    private final JwtProperties jwtProperties;

    private final PrivateKey privateKey;
    private final PrivateKey previousPrivateKey;

    @Getter private final RSAPublicKey publicKey;
    @Getter private final RSAPublicKey previousPublicKey;

    @Getter private final String keyId;
    @Getter private final String previousKeyId;

    private JwtDecoder nimbusJwtDecoder;
    private final boolean isIssuer;

    /**
     * Decodes and caches the signing key at construction time, so every
     * token operation avoids redundant Base64 decoding.
     */
    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        validateConfiguration();

        if (StringUtils.hasText(jwtProperties.getPrivateKey())) {
            this.isIssuer = true;
            this.privateKey = decodePrivateKey(jwtProperties.getPrivateKey());
            this.publicKey = derivePublicKey((RSAPrivateCrtKey) this.privateKey);

            boolean hasPreviousKey = StringUtils.hasText(jwtProperties.getPreviousPrivateKey());
            this.previousPrivateKey = hasPreviousKey ? decodePrivateKey(jwtProperties.getPreviousPrivateKey()) : null;
            this.previousPublicKey = previousPrivateKey != null ? derivePublicKey((RSAPrivateCrtKey) previousPrivateKey) : null;

            this.keyId = Jwks.builder().key(this.publicKey).idFromThumbprint().build().getId();
            this.previousKeyId = previousPublicKey != null
                    ? Jwks.builder().key(previousPublicKey).idFromThumbprint().build().getId()
                    : null;
        } else if (StringUtils.hasText(jwtProperties.getPublicKey())) {
            this.isIssuer = false;
            this.privateKey = null;
            this.previousPrivateKey = null;
            this.publicKey = decodePublicKey(jwtProperties.getPublicKey());

            boolean hasPreviousKey = StringUtils.hasText(jwtProperties.getPreviousPublicKey());
            this.previousPublicKey = hasPreviousKey ? decodePublicKey(jwtProperties.getPreviousPublicKey()) : null;

            this.keyId = Jwks.builder().key(this.publicKey).idFromThumbprint().build().getId();
            this.previousKeyId = previousPublicKey != null
                    ? Jwks.builder().key(previousPublicKey).idFromThumbprint().build().getId()
                    : null;
        } else if (StringUtils.hasText(jwtProperties.getJwksUri())) {
            this.isIssuer = false;
            this.privateKey = null;
            this.previousPrivateKey = null;
            this.publicKey = null;
            this.previousPublicKey = null;
            this.keyId = null;
            this.previousKeyId = null;
            this.nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwtProperties.getJwksUri()).build();
        } else {
            this.isIssuer = false;
            this.privateKey = null;
            this.previousPrivateKey = null;
            this.publicKey = null;
            this.previousPublicKey = null;
            this.keyId = null;
            this.previousKeyId = null;
        }
    }

    public String extractSubject(final String token) {
        if (nimbusJwtDecoder != null) {
            return nimbusJwtDecoder.decode(token).getSubject();
        }
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Every claim baked into the token at issue time (e.g. {@code org_id}, {@code roles}),
     * exposed as a plain {@code Map} so callers don't need jjwt on their own classpath.
     * {@code JwtAuthFilter} reads this to populate {@link JwtAuthenticationDetails} - services
     * needing a claim beyond the user id (which {@code UserByIdDetailsService.loadUserById}
     * already covers) go through {@code SecurityUtils} rather than re-parsing the token.
     */
    public Map<String, Object> extractClaims(final String token) {
        if (nimbusJwtDecoder != null) {
            return nimbusJwtDecoder.decode(token).getClaims();
        }
        return extractAllClaims(token);
    }

    public boolean isTokenValid(final String token, final SecurityPrincipal securityPrincipal) {
        try {
            final String subjectId = extractSubject(token);
            return subjectId.equals(securityPrincipal.getId().toString()) && isTokenNotExpired(token);
        } catch (Exception e) {
            log.debug("Token validation failed for principal {}: {}", securityPrincipal.getId(), e.getMessage());
            return false;
        }
    }

    public boolean isTokenValid(final String token) {
        try {
            if (nimbusJwtDecoder != null) {
                Jwt jwt = nimbusJwtDecoder.decode(token);
                return jwt.getExpiresAt() != null && jwt.getExpiresAt().isAfter(Instant.now());
            } else {
                extractAllClaims(token);
                return isTokenNotExpired(token);
            }
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public String generateToken(final SecurityPrincipal principal, final Map<String, Object> extraClaims) {
        if (!isIssuer) {
            throw new UnsupportedOperationException(
                    "This JwtService instance is configured for validation only and cannot generate tokens.");
        }
        Map<String, Object> claims = new HashMap<>(extraClaims);
        claims.put("id", principal.getId());
        return generateToken(claims, principal, jwtProperties.getAccessTokenExpiration());
    }

    private String generateToken(final Map<String, Object> claims, final SecurityPrincipal principal, long expiration) {
        Instant now = Instant.now();

        return Jwts.builder()
                .header().keyId(keyId).and()
                .claims(claims)
                .subject(principal.getId().toString())
                .issuer(jwtProperties.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expiration)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    private <T> T extractClaim(final String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private boolean isTokenNotExpired(final String token) {
        return !extractExpiration(token).isBefore(Instant.now());
    }

    public Instant extractExpiration(final String token) {
        if (nimbusJwtDecoder != null) {
            return nimbusJwtDecoder.decode(token).getExpiresAt();
        }
        return extractClaim(token, Claims::getExpiration).toInstant();
    }

    private Claims extractAllClaims(final String token) {
        if (nimbusJwtDecoder != null) {
            throw new IllegalStateException(
                    "extractAllClaims is not supported when configured via JWKS URI; use nimbusJwtDecoder directly");
        }
        return Jwts.parser()
                .keyLocator(new LocatorAdapter<>() {
                    @Override
                    protected Key locate(JwsHeader header) {
                        String kid = header.getKeyId();
                        if (keyId.equals(kid)) return publicKey;
                        if (previousKeyId != null && previousKeyId.equals(kid)) return previousPublicKey;
                        return null;
                    }
                })
                .requireIssuer(jwtProperties.getIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private PrivateKey decodePrivateKey(final String base64) {
        byte[] keyBytes = decodeBase64(base64);
        try {
            KeyFactory kf = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
            return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot load JWT private key", e);
        }
    }

    private RSAPublicKey decodePublicKey(final String base64) {
        byte[] keyBytes = decodeBase64(base64);
        try {
            KeyFactory kf = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
            return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot load JWT public key", e);
        }
    }

    /**
     * Accepts both standard and URL-safe Base64 (some secret managers / generators emit
     * '-'/'_' instead of '+'/'/'), so key loading doesn't depend on which variant the
     * upstream source happens to produce.
     */
    private byte[] decodeBase64(final String base64) {
        String normalized = base64.replace('-', '+').replace('_', '/');
        return Decoders.BASE64.decode(normalized);
    }

    private RSAPublicKey derivePublicKey(@NonNull final RSAPrivateCrtKey privateKey) {
        try {
            KeyFactory kf = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
            RSAPublicKeySpec spec = new RSAPublicKeySpec(
                    privateKey.getModulus(), privateKey.getPublicExponent());
            return (RSAPublicKey) kf.generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot derive JWT public key", e);
        }
    }

    private void validateConfiguration() {
        int keySources = 0;
        if (StringUtils.hasText(jwtProperties.getPrivateKey())) keySources++;
        if (StringUtils.hasText(jwtProperties.getPublicKey())) keySources++;
        if (StringUtils.hasText(jwtProperties.getJwksUri())) keySources++;

        if (keySources == 0) {
            throw new IllegalStateException(
                    "JWT configuration error: exactly one of [private-key, public-key, jwks-uri] must be provided");
        }
        if (keySources > 1) {
            throw new IllegalStateException(
                    "JWT configuration error: only one of [private-key, public-key, jwks-uri] can be provided at the same time");
        }
    }
}
