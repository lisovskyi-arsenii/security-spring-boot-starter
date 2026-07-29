package com.lisovskyi.security.autoconfigure.cookie;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

@RequiredArgsConstructor
public class CookieService {
    private final CookieProperties cookieProperties;

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    public void setAccessTokenCookie(HttpServletResponse response, String accessToken) {
        String path = buildFullPath(cookieProperties.getAccessTokenPath());
        buildCookie(
                response,
                cookieProperties.getAccessTokenName(),
                accessToken,
                cookieProperties.getAccessTokenMaxAge(),
                path
        );
    }

    public void clearAccessTokenCookie(HttpServletResponse response) {
        String path = buildFullPath(cookieProperties.getAccessTokenPath());
        buildCookie(
                response,
                cookieProperties.getAccessTokenName(),
                "",
                0,
                path
        );
    }

    public void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        String fullPath = buildFullPath(cookieProperties.getRefreshTokenPath());

        buildCookie(
                response,
                cookieProperties.getRefreshTokenName(),
                refreshToken,
                cookieProperties.getRefreshTokenMaxAge(),
                fullPath
        );
    }

    public void clearRefreshTokenCookie(HttpServletResponse response) {
        String fullPath = buildFullPath(cookieProperties.getRefreshTokenPath());

        buildCookie(
                response,
                cookieProperties.getRefreshTokenName(),
                "",
                0,
                fullPath
        );
    }

    private void buildCookie(
            HttpServletResponse response,
            String name,
            String value,
            long maxAge,
            String path
    ) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(cookieProperties.isSecure())
                .sameSite(cookieProperties.getSameSite())
                .path(path)
                .maxAge(maxAge)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private String buildFullPath(String partialPath) {
        String base = contextPath.replaceAll("/$", "");
        String path = partialPath.startsWith("/") ? partialPath : "/" + partialPath;

        return base + path;
    }
}