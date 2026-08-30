package com.lisovskyi.security.autoconfigure.cookie;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Optional;

@RequiredArgsConstructor
public class CookieService {

    private final CookieProperties cookieProperties;

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    public Optional<String> getAccessTokenCookie(@NonNull final HttpServletRequest request) {
        return getCookieValue(request, cookieProperties.getAccessTokenName());
    }

    public Optional<String> getRefreshTokenCookie(@NonNull final HttpServletRequest request) {
        return getCookieValue(request, cookieProperties.getRefreshTokenName());
    }

    public void setAccessTokenCookie(@NonNull final HttpServletResponse response, final String accessToken) {
        String path = buildFullPath(cookieProperties.getAccessTokenPath());
        buildCookie(
                response,
                cookieProperties.getAccessTokenName(),
                accessToken,
                cookieProperties.getAccessTokenMaxAge(),
                path
        );
    }

    public void clearAccessTokenCookie(@NonNull final HttpServletResponse response) {
        final String path = buildFullPath(cookieProperties.getAccessTokenPath());
        buildCookie(
                response,
                cookieProperties.getAccessTokenName(),
                "",
                0,
                path
        );
    }

    public void setRefreshTokenCookie(@NonNull final HttpServletResponse response, final String refreshToken) {
        final String fullPath = buildFullPath(cookieProperties.getRefreshTokenPath());

        buildCookie(
                response,
                cookieProperties.getRefreshTokenName(),
                refreshToken,
                cookieProperties.getRefreshTokenMaxAge(),
                fullPath
        );
    }

    public void clearRefreshTokenCookie(@NonNull final HttpServletResponse response) {
        final String fullPath = buildFullPath(cookieProperties.getRefreshTokenPath());

        buildCookie(
                response,
                cookieProperties.getRefreshTokenName(),
                "",
                0,
                fullPath
        );
    }

    private void buildCookie(
            @NonNull final HttpServletResponse response,
            @NonNull final String name,
            @NonNull final String value,
            long maxAge,
            @NonNull final String path
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
        return UriComponentsBuilder.fromPath(contextPath)
                .path(partialPath)
                .toUriString();
    }

    private Optional<String> getCookieValue(@NonNull final HttpServletRequest request, final String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(name)) {
                return Optional.of(cookie.getValue());
            }
        }

        return Optional.empty();
    }
}