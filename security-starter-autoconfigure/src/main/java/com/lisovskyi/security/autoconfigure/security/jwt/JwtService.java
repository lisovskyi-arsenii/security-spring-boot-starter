package com.lisovskyi.security.autoconfigure.security.jwt;

import com.lisovskyi.security.autoconfigure.security.SecurityPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
public class JwtService {

    private final JwtProperties jwtProperties;
    private final SecretKey cachedSigningKey;

    /**
     * Decodes and caches the signing key at construction time, so every
     * token operation avoids redundant Base64 decoding.
     */
    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSigningKey());
        this.cachedSigningKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String generateToken(SecurityPrincipal securityPrincipal) {
        Map<String, Object> claims = new HashMap<>();

        claims.put("id", securityPrincipal.getId());
        claims.put("role", securityPrincipal.getRole());

        return generateToken(claims, securityPrincipal, jwtProperties.getAccessTokenExpiration());
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

    private String generateToken(Map<String, Object> claims, SecurityPrincipal securityPrincipal, long expiration) {
        Instant now = Instant.now();
        String subjectId = securityPrincipal.getId().toString();

        return Jwts.builder()
                .claims(claims)
                .subject(subjectId)
                .issuer(jwtProperties.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expiration)))
                .signWith(cachedSigningKey)
                .compact();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).toInstant().isBefore(Instant.now());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(cachedSigningKey)
                .requireIssuer(jwtProperties.getIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
