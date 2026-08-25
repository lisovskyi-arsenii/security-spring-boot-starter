package com.lisovskyi.security.autoconfigure.security.jwt;

import com.lisovskyi.security.autoconfigure.security.SecurityPrincipal;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Jwks;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
public class JwtService {

    private final JwtProperties jwtProperties;
    private final PrivateKey privateKey;
    @Getter private final RSAPublicKey publicKey;
    private final PrivateKey previousPrivateKey;
    @Getter private final RSAPublicKey previousPublicKey;
    @Getter private final String keyId;
    @Getter private final String previousKeyId;

    /**
     * Decodes and caches the signing key at construction time, so every
     * token operation avoids redundant Base64 decoding.
     */
    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.privateKey = decodePrivateKey(jwtProperties.getPrivateKey());
        this.publicKey = derivePublicKey((RSAPrivateCrtKey) this.privateKey);
        boolean hasPreviousKey = StringUtils.hasText(jwtProperties.getPreviousPrivateKey());
        this.previousPrivateKey = hasPreviousKey ? decodePrivateKey(jwtProperties.getPreviousPrivateKey()) : null;
        this.previousPublicKey = previousPrivateKey != null ? derivePublicKey((RSAPrivateCrtKey) previousPrivateKey) : null;
        this.keyId = Jwks.builder().key(this.publicKey).idFromThumbprint().build().getId();
        this.previousKeyId = previousPublicKey != null ? Jwks.builder().key(previousPublicKey).idFromThumbprint().build().getId() : null;
    }

    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Every claim baked into the token at issue time (e.g. {@code org_id}, {@code roles}),
     * exposed as a plain {@code Map} so callers don't need jjwt on their own classpath.
     * {@code JwtAuthFilter} reads this to populate {@link JwtAuthenticationDetails} - services
     * needing a claim beyond the user id (which {@code UserByIdDetailsService.loadUserById}
     * already covers) go through {@code SecurityUtils} rather than re-parsing the token.
     */
    public Map<String, Object> extractClaims(String token) {
        return extractAllClaims(token);
    }

    public boolean isTokenValid(String token, SecurityPrincipal securityPrincipal) {
        try {
            final String subjectId = extractSubject(token);
            return (subjectId.equals(securityPrincipal.getId().toString()) && !isTokenExpired(token));
        } catch (Exception e) {
            log.debug("Token validation failed for principal {}: {}", securityPrincipal.getId(), e.getMessage());
            return false;
        }
    }

    public boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public String generateToken(SecurityPrincipal principal, Map<String, Object> extraClaims) {
        Map<String, Object> claims = new HashMap<>(extraClaims);
        claims.put("id", principal.getId());
        return generateToken(claims, principal, jwtProperties.getAccessTokenExpiration());
    }

    private String generateToken(Map<String, Object> claims, SecurityPrincipal principal, long expiration) {
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

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).isBefore(Instant.now());
    }

    public Instant extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration).toInstant();
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .keyLocator(new LocatorAdapter<Key>() {
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

    private PrivateKey decodePrivateKey(String base64) {
        byte[] keyBytes = Decoders.BASE64.decode(base64);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot load JWT private key", e);
        }
    }

    private RSAPublicKey derivePublicKey(RSAPrivateCrtKey privateKey) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec spec = new RSAPublicKeySpec(
                    privateKey.getModulus(), privateKey.getPublicExponent());
            return (RSAPublicKey) kf.generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot derive JWT public key", e);
        }
    }
}
