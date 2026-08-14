package com.lisovskyi.security.autoconfigure.cookie;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

import java.util.Optional;

@RequiredArgsConstructor
public class CookieService {
    private final CookieProperties cookieProperties;

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    public Optional<String> getAccessTokenCookie(HttpServletRequest request) {
        return getCookieValue(request, cookieProperties.getAccessTokenName());
    }

    public Optional<String> getRefreshTokenCookie(HttpServletRequest request) {
        return getCookieValue(request, cookieProperties.getRefreshTokenName());
    }

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

    private Optional<String> getCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(name)) {
                return Optional.of(cookie.getValue());
            }
        }

        return Optional.empty();
    }
}