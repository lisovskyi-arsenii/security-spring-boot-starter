package com.lisovskyi.security.autoconfigure.security.jwt;

import com.lisovskyi.security.autoconfigure.cookie.CookieService;
import com.lisovskyi.security.autoconfigure.security.UserByIdDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

public class JwtAuthFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final CookieService cookieService;
    private final UserByIdDetailsService userDetailsService;
    private final JwtBlacklistService jwtBlacklistService;

    private final HandlerExceptionResolver exceptionResolver;

    public JwtAuthFilter(
            @NonNull final JwtService jwtService,
            @NonNull final CookieService cookieService,
            @NonNull final UserByIdDetailsService userDetailsService,
            @NonNull final JwtBlacklistService jwtBlacklistService,
            @NonNull @Qualifier("handlerExceptionResolver") final HandlerExceptionResolver handlerExceptionResolver
    ) {
        this.jwtService = jwtService;
        this.cookieService = cookieService;
        this.userDetailsService = userDetailsService;
        this.jwtBlacklistService = jwtBlacklistService;
        this.exceptionResolver = handlerExceptionResolver;
    }

    @Override
    protected void doFilterInternal(
            @NonNull final HttpServletRequest request,
            @NonNull final HttpServletResponse response,
            @NonNull final FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String jwt = extractTokenFromHeader(request);

            if (jwt == null) {
                jwt = cookieService.getAccessTokenCookie(request)
                        .orElse(null);
            }

            if (jwt == null || jwt.isBlank()) {
                filterChain.doFilter(request, response);
                return;
            }

            if (jwtBlacklistService.isBlacklisted(jwt)) {
                throw new CredentialsExpiredException("JWT is blacklisted");
            }

            if (!jwtService.isTokenValid(jwt)) {
                filterChain.doFilter(request, response);
                return;
            }

            final String userIdStr = jwtService.extractSubject(jwt);

            if (userIdStr != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                final long userId = Long.parseLong(userIdStr);
                authenticateUser(request, jwt, userId);
            }

            filterChain.doFilter(request, response);

        } catch (Exception ex) {
            exceptionResolver.resolveException(request, response, null, ex);
        }
    }

    private String extractTokenFromHeader(@NonNull final HttpServletRequest request) {
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    private void authenticateUser(@NonNull final HttpServletRequest request, final String jwt, final Long userId) {
        final UserDetails userDetails = userDetailsService.loadUserById(userId);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        WebAuthenticationDetails webDetails = new WebAuthenticationDetailsSource().buildDetails(request);
        authToken.setDetails(new JwtAuthenticationDetails(webDetails, jwtService.extractClaims(jwt)));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
