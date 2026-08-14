package com.lisovskyi.security.autoconfigure.security.jwt;

import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.RsaPublicJwk;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final JwtService jwtService;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        RsaPublicJwk jwk = Jwks.builder()
                .key(jwtService.getPublicKey())
                .id(jwtService.getKeyId())
                .build();

        return Jwks.set().add(jwk).build();
    }
}
