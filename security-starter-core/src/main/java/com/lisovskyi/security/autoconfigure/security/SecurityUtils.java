package com.lisovskyi.security.autoconfigure.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public final class SecurityUtils {

    private SecurityUtils() {}

    public static Optional<Authentication> getCurrentAuthentication() {
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication());
    }

    public static Optional<SecurityPrincipal> getCurrentPrincipal() {
        return getCurrentAuthentication()
                .map(Authentication::getPrincipal)
                .filter(SecurityPrincipal.class::isInstance)
                .map(SecurityPrincipal.class::cast);
    }

    public static Optional<Long> getCurrentUserId() {
        return getCurrentPrincipal().map(SecurityPrincipal::getId);
    }
}
