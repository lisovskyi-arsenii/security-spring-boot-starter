package com.lisovskyi.security.autoconfigure.security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Map;

/**
 * What {@link Authentication#getDetails()} carries after {@code JwtAuthFilter} authenticates a
 * request: the usual request metadata (remote IP, session id) alongside every claim from the JWT
 * payload (e.g. {@code org_id}, {@code roles}) that {@code UserByIdDetailsService.loadUserById}
 * has no way to know about, since it's only given the user id.
 *
 * <p>Deliberately not folded into the principal ({@code SecurityPrincipal}/{@code UserDetails}):
 * that would force every implementation across every service (e.g. user-service's
 * {@code SecurityUser}) to grow a claims field, and would break existing
 * {@code @CurrentUser SecurityUser} bindings the moment the principal type changed. Reading
 * through {@link com.lisovskyi.security.autoconfigure.security.SecurityUtils} instead keeps this
 * additive.
 */
public record JwtAuthenticationDetails(WebAuthenticationDetails webDetails, Map<String, Object> claims) {

    public Object claim(String name) {
        return claims.get(name);
    }
}
