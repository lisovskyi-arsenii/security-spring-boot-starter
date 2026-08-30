package com.lisovskyi.security.autoconfigure.security;

import com.lisovskyi.security.autoconfigure.security.jwt.JwtAuthenticationDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public final class SecurityUtils {

    private SecurityUtils() {
        throw new UnsupportedOperationException();
    }

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

    /**
     * Any claim baked into the JWT at issue time (e.g. {@code org_id}, {@code roles}) - the
     * escape hatch for data {@code UserByIdDetailsService.loadUserById} has no way to provide,
     * since it's only ever given the user id. Populated by {@code JwtAuthFilter}; empty for
     * requests authenticated some other way (or not authenticated at all).
     */
    public static Optional<Object> getCurrentClaim(String name) {
        return getCurrentAuthentication()
                .map(Authentication::getDetails)
                .filter(JwtAuthenticationDetails.class::isInstance)
                .map(JwtAuthenticationDetails.class::cast)
                .map(details -> details.claim(name));
    }
}
