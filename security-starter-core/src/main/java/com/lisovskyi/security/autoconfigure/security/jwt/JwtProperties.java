package com.lisovskyi.security.autoconfigure.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {
    private String privateKey;
    private String previousPrivateKey;

    private String publicKey;
    private String previousPublicKey;

    private String jwksUri;

    private long accessTokenExpiration = 900000; // 15 mins
    private long refreshTokenExpiration = 604800000; // 7 days

    private String issuer = "lisovskyi-security-service";

    public String getPrivateKey() { return privateKey; }

    public void setPrivateKey(String privateKey) { this.privateKey = privateKey; }

    public String getPreviousPrivateKey() { return previousPrivateKey; }

    public void setPreviousPrivateKey(String previousPrivateKey) { this.previousPrivateKey = previousPrivateKey; }

    public String getPublicKey() { return publicKey; }

    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

    public String getPreviousPublicKey() { return previousPublicKey; }

    public void setPreviousPublicKey(String previousPublicKey) { this.previousPublicKey = previousPublicKey; }

    public String getJwksUri() { return jwksUri; }

    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }

    public long getAccessTokenExpiration() { return accessTokenExpiration; }

    public void setAccessTokenExpiration(long accessTokenExpiration) { this.accessTokenExpiration = accessTokenExpiration; }

    public long getRefreshTokenExpiration() { return refreshTokenExpiration; }

    public void setRefreshTokenExpiration(long refreshTokenExpiration) { this.refreshTokenExpiration = refreshTokenExpiration; }

    public String getIssuer() { return issuer; }

    public void setIssuer(String issuer) { this.issuer = issuer; }
}
