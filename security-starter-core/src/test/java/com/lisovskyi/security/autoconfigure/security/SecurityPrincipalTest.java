package com.lisovskyi.security.autoconfigure.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityPrincipalTest {

    private SecurityPrincipal principalWithRole(String role) {
        return new SecurityPrincipal() {
            @Override
            public Long getId() {
                return 1L;
            }

            @Override
            public String getRole() {
                return role;
            }

            @Override
            public String getPassword() {
                return null;
            }

            @Override
            public String getUsername() {
                return "user@example.com";
            }
        };
    }

    @ParameterizedTest
    @CsvSource({
        "ADMIN, ROLE_ADMIN",
        "USER, ROLE_USER"
    })
    void prefixesTheRawRoleWithRolePrefix(String rawRole, String expectedAuthority) {
        Collection<? extends GrantedAuthority> authorities = principalWithRole(rawRole).getAuthorities();

        assertThat(authorities).extracting(GrantedAuthority::getAuthority).containsExactly(expectedAuthority);
    }

    @Test
    void doesNotDoublePrefixARoleThatAlreadyHasIt() {
        Collection<? extends GrantedAuthority> authorities = principalWithRole("ROLE_ADMIN").getAuthorities();

        assertThat(authorities).extracting(GrantedAuthority::getAuthority).containsExactly("ROLE_ADMIN");
    }

    @Test
    void producesExactlyOneAuthority() {
        assertThat(principalWithRole("USER").getAuthorities()).hasSize(1);
    }
}
