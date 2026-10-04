package com.lisovskyi.security.autoconfigure.security.jwt;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns the JWT's {@code roles} claim into Spring Security authorities.
 *
 * <p>Each role becomes {@code ROLE_<role>} - a value that already starts with {@code ROLE_} is kept
 * as is, so {@code hasRole("OWNER")} works whether the token carries {@code OWNER} or
 * {@code ROLE_OWNER}. A missing claim, one that is not a collection, and null/blank entries all
 * yield nothing rather than failing: a malformed claim must not break authentication.
 */
final class JwtRoleAuthorities {

    static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    private JwtRoleAuthorities() {
        throw new UnsupportedOperationException();
    }

    static List<GrantedAuthority> fromClaims(final Map<String, Object> claims) {
        if (claims == null || !(claims.get(ROLES_CLAIM) instanceof Collection<?> roles)) {
            return List.of();
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        for (Object role : roles) {
            if (role == null || role.toString().isBlank()) {
                continue;
            }

            String name = role.toString().strip();
            authorities.add(new SimpleGrantedAuthority(name.startsWith(ROLE_PREFIX) ? name : ROLE_PREFIX + name));
        }

        return authorities;
    }

    /** {@code base} followed by {@code extra}, without duplicates, order preserved. */
    static List<GrantedAuthority> merge(
            final Collection<? extends GrantedAuthority> base,
            final Collection<? extends GrantedAuthority> extra
    ) {
        Set<GrantedAuthority> merged = new LinkedHashSet<>(base);
        merged.addAll(extra);
        return new ArrayList<>(merged);
    }
}
