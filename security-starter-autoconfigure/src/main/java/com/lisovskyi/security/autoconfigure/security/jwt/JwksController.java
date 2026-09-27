package com.lisovskyi.security.autoconfigure.security.jwt;

import io.jsonwebtoken.security.JwkSetBuilder;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.RsaPublicJwk;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

/**
 * Реєструється лише коли є приватний ключ (app.jwt.private-key) - див.
 * {@code @ConditionalOnProperty} на {@code SecurityAutoConfiguration#jwksController()},
 * не тут: клас конструюється вручну через {@code new}, тому class-level
 * {@code @Conditional} на ньому самому Spring ніколи не оцінює.
 */
@RestController
public class JwksController {

    private static final Duration CACHE_MAX_AGE = Duration.ofMinutes(15);

    private final JwtService jwtService;

    public JwksController(final JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {
        RsaPublicJwk jwk = Jwks.builder()
                .key(jwtService.getPublicKey())
                .id(jwtService.getKeyId())
                .build();

        JwkSetBuilder jwkSetBuilder = Jwks.set();
        jwkSetBuilder.add(jwk);
        if (jwtService.getPreviousPublicKey() != null) {
            RsaPublicJwk previousJwk = Jwks.builder()
                    .key(jwtService.getPreviousPublicKey())
                    .id(jwtService.getPreviousKeyId())
                    .build();
            jwkSetBuilder.add(previousJwk);
        }

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(CACHE_MAX_AGE).cachePublic())
                .body(jwkSetBuilder.build());
    }
}
