package com.lisovskyi.security.autoconfigure.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class SecurityMdcFilter extends OncePerRequestFilter {

    private static final String USER_ID_MDC_KEY = "userId";
    private static final String CLIENT_IP_MDC_KEY = "clientIp";

    /**
     * Header set by reverse proxies (nginx, AWS ALB, etc.) with the
     * real client IP. May contain a comma-separated chain of IPs when
     * requests pass through multiple proxies; only the first is used.
     */
    private static final String X_FORWARDED_FOR = "X-Forwarded-For";

    @Override
    protected void doFilterInternal(
            @NonNull final HttpServletRequest request,
            @NonNull final HttpServletResponse response,
            @NonNull final FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            SecurityUtils.getCurrentUserId().ifPresent(id -> MDC.put(USER_ID_MDC_KEY, id.toString()));
            MDC.put(CLIENT_IP_MDC_KEY, extractClientIp(request));
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(USER_ID_MDC_KEY);
            MDC.remove(CLIENT_IP_MDC_KEY);
        }
    }

    /**
     * Resolves the real client IP address. When the application runs behind
     * a reverse proxy (nginx, load balancer), the actual IP is stored in the
     * {@code X-Forwarded-For} header, not in {@code request.getRemoteAddr()}.
     */
    private String extractClientIp(@NonNull final HttpServletRequest request) {
        final String xff = request.getHeader(X_FORWARDED_FOR);
        if (xff != null && !xff.isBlank()) {
            // X-Forwarded-For may be a comma-separated list: "client, proxy1, proxy2"
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
