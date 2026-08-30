package com.lisovskyi.security.autoconfigure.cookie;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.cookie")
public class CookieProperties {

    private String accessTokenName = "access_token";
    private String refreshTokenName = "refresh_token";

    private String accessTokenPath = "/";
    private String refreshTokenPath = "/auth/refresh";

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
}
