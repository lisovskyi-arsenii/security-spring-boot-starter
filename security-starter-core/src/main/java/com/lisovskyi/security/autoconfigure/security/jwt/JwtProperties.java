package com.lisovskyi.security.autoconfigure.security.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {
    private String privateKey;
    private String previousPrivateKey;
    private long accessTokenExpiration = 900000; // 15 mins
    private long refreshTokenExpiration = 604800000; // 7 days
    private String issuer = "lisovskyi-security-service";
}
