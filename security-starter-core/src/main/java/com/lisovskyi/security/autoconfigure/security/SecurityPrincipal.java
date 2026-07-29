package com.lisovskyi.security.autoconfigure.security;

import lombok.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public interface SecurityPrincipal extends UserDetails {

    Object getId();

    /**
     * Returns the role of this principal. May be provided with or without
     * the {@code ROLE_} prefix — the default {@link #getAuthorities()} impl
     * normalises it automatically, so {@code hasRole("ADMIN")} and
     * {@code hasAuthority("ROLE_ADMIN")} both work out of the box.
     */
    String getRole();

    /**
     * Builds the authority list from {@link #getRole()}.
     * Normalises the value so that Spring Security's {@code hasRole()}
     * (which expects a {@code ROLE_} prefix) and {@code hasAuthority()}
     * (which uses the raw value) both work correctly regardless of how the
     * role string is stored in the database or JWT.
     */
    @Override
    default @NonNull Collection<? extends GrantedAuthority> getAuthorities() {
        String role = getRole();
        String authority = (role != null && role.startsWith("ROLE_")) ? role : "ROLE_" + role;
        return List.of(new SimpleGrantedAuthority(authority));
    }
}
