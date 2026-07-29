package com.lisovskyi.security.autoconfigure.security.jwt;

import com.lisovskyi.security.autoconfigure.cookie.CookieProperties;
import com.lisovskyi.security.autoconfigure.security.UserByIdDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

public class JwtAuthFilter extends OncePerRequestFilter {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserByIdDetailsService userDetailsService;
    private final JwtBlacklistService jwtBlacklistService;
    private final HandlerExceptionResolver exceptionResolver;
    private final CookieProperties cookieProperties;

    public JwtAuthFilter(
            JwtService jwtService,
            UserByIdDetailsService userDetailsService,
            JwtBlacklistService jwtBlacklistService,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver,
            CookieProperties cookieProperties
    ) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.jwtBlacklistService = jwtBlacklistService;
        this.exceptionResolver = handlerExceptionResolver;
        this.cookieProperties = cookieProperties;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String jwt = extractTokenFromHeader(request);

            if (jwt == null) {
                jwt = extractTokenFromCookie(request);
            }

            if (jwt == null || jwt.isBlank()) {
                filterChain.doFilter(request, response);
                return;
            }

            if (jwtBlacklistService.isBlacklisted(jwt)) {
                throw new CredentialsExpiredException("JWT is blacklisted");
            }

            final String userIdStr = jwtService.extractSubject(jwt);

            if (userIdStr != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                authenticateUser(request, jwt, userIdStr);
            }

            filterChain.doFilter(request, response);

        } catch (Exception ex) {
            exceptionResolver.resolveException(request, response, null, ex);
        }
    }

    private String extractTokenFromHeader(HttpServletRequest request) {
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        final Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieProperties.getAccessTokenName().equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void authenticateUser(HttpServletRequest request, String jwt, String userId) {
        UserDetails userDetails = userDetailsService.loadUserById(userId);

        if (jwtService.isTokenValid(jwt)) {
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
    }
}
