package com.lisovskyi.security.autoconfigure.security.jwt;

import com.lisovskyi.security.autoconfigure.security.SecurityPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Jwks;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);
    private static final String KEY_FACTORY_ALGORITHM = "RSA";

    private final JwtProperties jwtProperties;
    private final PrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final RSAPublicKey previousPublicKey;
    private final String keyId;
    private final String previousKeyId;
    private final boolean isIssuer;

    private final JwtParser jwtParser;
    private final JwtDecoder nimbusJwtDecoder;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        validateConfiguration();

        if (StringUtils.hasText(jwtProperties.getPrivateKey())) {
            this.isIssuer = true;
            this.privateKey = decodePrivateKey(jwtProperties.getPrivateKey());
            this.publicKey = derivePublicKey(this.privateKey);

            boolean hasPreviousKey = StringUtils.hasText(jwtProperties.getPreviousPrivateKey());
            PrivateKey previousPrivateKey = hasPreviousKey ? decodePrivateKey(jwtProperties.getPreviousPrivateKey()) : null;
            this.previousPublicKey = previousPrivateKey != null ? derivePublicKey(previousPrivateKey) : null;

            this.keyId = Jwks.builder().key(this.publicKey).idFromThumbprint().build().getId();
            this.previousKeyId = previousPublicKey != null
                    ? Jwks.builder().key(previousPublicKey).idFromThumbprint().build().getId()
                    : null;
            this.nimbusJwtDecoder = null;
            this.jwtParser = buildJwtParser();

        } else if (StringUtils.hasText(jwtProperties.getPublicKey())) {
            this.isIssuer = false;
            this.privateKey = null;
            this.publicKey = decodePublicKey(jwtProperties.getPublicKey());

            boolean hasPreviousKey = StringUtils.hasText(jwtProperties.getPreviousPublicKey());
            this.previousPublicKey = hasPreviousKey ? decodePublicKey(jwtProperties.getPreviousPublicKey()) : null;

            this.keyId = Jwks.builder().key(this.publicKey).idFromThumbprint().build().getId();
            this.previousKeyId = previousPublicKey != null
                    ? Jwks.builder().key(previousPublicKey).idFromThumbprint().build().getId()
                    : null;
            this.nimbusJwtDecoder = null;
            this.jwtParser = buildJwtParser();

        } else if (StringUtils.hasText(jwtProperties.getJwksUri())) {
            this.isIssuer = false;
            this.privateKey = null;
            this.publicKey = null;
            this.previousPublicKey = null;
            this.keyId = null;
            this.previousKeyId = null;
            this.jwtParser = null;
            this.nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwtProperties.getJwksUri()).build();

        } else {
            this.isIssuer = false;
            this.privateKey = null;
            this.publicKey = null;
            this.previousPublicKey = null;
            this.keyId = null;
            this.previousKeyId = null;
            this.jwtParser = null;
            this.nimbusJwtDecoder = null;
        }
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPublicKey getPreviousPublicKey() {
        return previousPublicKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getPreviousKeyId() {
        return previousKeyId;
    }

    public String extractSubject(final String token) {
        if (nimbusJwtDecoder != null) {
            return nimbusJwtDecoder.decode(token).getSubject();
        }
        return extractClaim(token, Claims::getSubject);
    }

    public Map<String, Object> extractClaims(final String token) {
        if (nimbusJwtDecoder != null) {
            return nimbusJwtDecoder.decode(token).getClaims();
        }
        return extractAllClaims(token);
    }

    public Instant extractExpiration(final String token) {
        if (nimbusJwtDecoder != null) {
            return nimbusJwtDecoder.decode(token).getExpiresAt();
        }
        return extractClaim(token, Claims::getExpiration).toInstant();
    }

    public boolean isTokenValid(final String token, final String expectedSubject) {
        try {
            final String subjectId = extractSubject(token);
            return subjectId.equals(expectedSubject);
        } catch (io.jsonwebtoken.JwtException | org.springframework.security.oauth2.jwt.JwtException | IllegalArgumentException e) {
            log.debug("Token validation failed for subject {}: {}", expectedSubject, e.getMessage());
            return false;
        }
    }

    public boolean isTokenValid(final String token, final SecurityPrincipal principal) {
        return isTokenValid(token, principal.getId().toString());
    }

    public boolean isTokenValid(final String token) {
        try {
            if (nimbusJwtDecoder != null) {
                Jwt jwt = nimbusJwtDecoder.decode(token);
                return jwt.getExpiresAt() != null && jwt.getExpiresAt().isAfter(Instant.now());
            } else {
                extractAllClaims(token);
                return true;
            }
        } catch (io.jsonwebtoken.JwtException | org.springframework.security.oauth2.jwt.JwtException | IllegalArgumentException e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public String generateToken(final String subject, final Map<String, Object> extraClaims) {
        if (!isIssuer) {
            throw new UnsupportedOperationException(
                    "This JwtService instance is configured for validation only and cannot generate tokens."
            );
        }
        Map<String, Object> claims = (extraClaims != null) ? new HashMap<>(extraClaims) : new HashMap<>();
        claims.put("id", subject);
        return generateToken(claims, subject, jwtProperties.getAccessTokenExpiration());
    }

    public String generateToken(final SecurityPrincipal principal, final Map<String, Object> extraClaims) {
        return generateToken(principal.getId().toString(), extraClaims);
    }

    private String generateToken(final Map<String, Object> claims, final String subject, long expiration) {
        Instant now = Instant.now();

        return Jwts.builder()
                .header().keyId(keyId).and()
                .claims(claims)
                .subject(subject)
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

    private Claims extractAllClaims(final String token) {
        if (jwtParser == null) {
            throw new IllegalStateException(
                    "extractAllClaims is not supported when configured via JWKS URI; use nimbusJwtDecoder directly");
        }
        return jwtParser.parseSignedClaims(token).getPayload();
    }

    private JwtParser buildJwtParser() {
        var builder = Jwts.parser()
                .keyLocator(new LocatorAdapter<>() {
                    @Override
                    protected Key locate(JwsHeader header) {
                        String kid = header.getKeyId();
                        if (kid == null) {
                            return publicKey;
                        }
                        if (keyId != null && keyId.equals(kid)) {
                            return publicKey;
                        }
                        if (previousKeyId != null && previousKeyId.equals(kid)) {
                            return previousPublicKey;
                        }
                        return null;
                    }
                });

        if (StringUtils.hasText(jwtProperties.getIssuer())) {
            builder.requireIssuer(jwtProperties.getIssuer());
        }
        return builder.build();
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

    private byte[] decodeBase64(final String base64) {
        String normalized = base64.replace('-', '+').replace('_', '/');
        return Decoders.BASE64.decode(normalized);
    }

    private RSAPublicKey derivePublicKey(@NonNull final PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey crtKey)) {
            throw new IllegalStateException("Private key does not contain CRT components to derive public key");
        }
        try {
            KeyFactory kf = KeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
            RSAPublicKeySpec spec = new RSAPublicKeySpec(
                    crtKey.getModulus(), crtKey.getPublicExponent());
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

        if (keySources != 1) {
            throw new IllegalStateException(
                    "JWT configuration error: exactly one of [private-key, public-key, jwks-uri] must be provided"
            );
        }
    }
}
