package com.lisovskyi.security.autoconfigure.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class JwtRoleAuthoritiesTest {

    private static Map<String, Object> claims(Object roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);
        return claims;
    }

    @Test
    void prefixesEachRoleWithROLE_() {
        assertThat(JwtRoleAuthorities.fromClaims(claims(List.of("OWNER", "ADMIN"))))
                .extracting(Object::toString)
                .containsExactly("ROLE_OWNER", "ROLE_ADMIN");
    }

    @Test
    void keepsAValueThatAlreadyHasThePrefix() {
        assertThat(JwtRoleAuthorities.fromClaims(claims(List.of("ROLE_OWNER"))))
                .extracting(Object::toString)
                .containsExactly("ROLE_OWNER");
    }

    @Test
    void trimsWhitespace() {
        assertThat(JwtRoleAuthorities.fromClaims(claims(List.of("  LAWYER "))))
                .extracting(Object::toString)
                .containsExactly("ROLE_LAWYER");
    }

    @Test
    void aMissingNullOrMalformedClaimGrantsNothing_andNeverThrows() {
        assertThat(JwtRoleAuthorities.fromClaims(Map.of())).isEmpty();
        assertThat(JwtRoleAuthorities.fromClaims(null)).isEmpty();
        assertThat(JwtRoleAuthorities.fromClaims(claims(null))).isEmpty();
        assertThat(JwtRoleAuthorities.fromClaims(claims("OWNER"))).as("a string, not a list").isEmpty();
        assertThat(JwtRoleAuthorities.fromClaims(claims(42))).isEmpty();
    }

    @Test
    void skipsNullAndBlankEntries() {
        List<Object> roles = new java.util.ArrayList<>();
        roles.add(null);
        roles.add("");
        roles.add("   ");
        roles.add("OWNER");

        assertThat(JwtRoleAuthorities.fromClaims(claims(roles)))
                .extracting(Object::toString)
                .containsExactly("ROLE_OWNER");
    }

    @Test
    void mergeKeepsTheBaseFirst_andDropsDuplicates() {
        var merged = JwtRoleAuthorities.merge(
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                List.of(new SimpleGrantedAuthority("ROLE_OWNER"), new SimpleGrantedAuthority("ROLE_USER")));

        assertThat(merged).extracting(Object::toString).containsExactly("ROLE_USER", "ROLE_OWNER");
    }
}
