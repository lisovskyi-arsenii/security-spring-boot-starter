package com.lisovskyi.security.autoconfigure.cookie;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.cookie")
public class CookieProperties {

    private String accessTokenName = "access_token";
    private String refreshTokenName = "refresh_token";

    private String accessTokenPath = "/";
    private String refreshTokenPath = "/auth";

    private long accessTokenMaxAge = 900; // 15 minutes in seconds
    private long refreshTokenMaxAge = 604800; // 7 days in seconds

    private String domain;
    private String sameSite = "Strict";

    private boolean secure = true;
    private boolean httpOnly = true;

    // Параметри для CSRF
    private String csrfCookiePath = "/";
    private String csrfCookieName = "XSRF-TOKEN";
    private String csrfCookieDomain;
    private String csrfSameSite = "Lax";

    public String getAccessTokenName() { return accessTokenName; }

    public void setAccessTokenName(String accessTokenName) { this.accessTokenName = accessTokenName; }

    public String getRefreshTokenName() { return refreshTokenName; }

    public void setRefreshTokenName(String refreshTokenName) { this.refreshTokenName = refreshTokenName; }

    public String getAccessTokenPath() { return accessTokenPath; }

    public void setAccessTokenPath(String accessTokenPath) { this.accessTokenPath = accessTokenPath; }

    public String getRefreshTokenPath() { return refreshTokenPath; }

    public void setRefreshTokenPath(String refreshTokenPath) { this.refreshTokenPath = refreshTokenPath; }

    public long getAccessTokenMaxAge() { return accessTokenMaxAge; }

    public void setAccessTokenMaxAge(long accessTokenMaxAge) { this.accessTokenMaxAge = accessTokenMaxAge; }

    public long getRefreshTokenMaxAge() { return refreshTokenMaxAge; }

    public void setRefreshTokenMaxAge(long refreshTokenMaxAge) { this.refreshTokenMaxAge = refreshTokenMaxAge; }

    public String getDomain() { return domain; }

    public void setDomain(String domain) { this.domain = domain; }

    public String getSameSite() { return sameSite; }

    public void setSameSite(String sameSite) { this.sameSite = sameSite; }

    public boolean isSecure() { return secure; }

    public void setSecure(boolean secure) { this.secure = secure; }

    public boolean isHttpOnly() { return httpOnly; }

    public void setHttpOnly(boolean httpOnly) { this.httpOnly = httpOnly; }

    public String getCsrfCookiePath() { return csrfCookiePath; }

    public void setCsrfCookiePath(String csrfCookiePath) { this.csrfCookiePath = csrfCookiePath; }

    public String getCsrfCookieName() { return csrfCookieName; }

    public void setCsrfCookieName(String csrfCookieName) { this.csrfCookieName = csrfCookieName; }

    public String getCsrfCookieDomain() { return csrfCookieDomain; }

    public void setCsrfCookieDomain(String csrfCookieDomain) { this.csrfCookieDomain = csrfCookieDomain; }

    public String getCsrfSameSite() { return csrfSameSite; }

    public void setCsrfSameSite(String csrfSameSite) { this.csrfSameSite = csrfSameSite; }
}
