package com.lisovskyi.security.autoconfigure.security;

import com.lisovskyi.security.autoconfigure.security.jwt.JwtAuthenticationDetails;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityUtilsTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private SecurityPrincipal principal(Long id) {
        return new SecurityPrincipal() {
            @Override
            public Long getId() {
                return id;
            }

            @Override
            public String getRole() {
                return "USER";
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

    @Test
    void noAuthenticationYieldsAllEmptyOptionals() {
        assertThat(SecurityUtils.getCurrentAuthentication()).isEmpty();
        assertThat(SecurityUtils.getCurrentPrincipal()).isEmpty();
        assertThat(SecurityUtils.getCurrentUserId()).isEmpty();
        assertThat(SecurityUtils.getCurrentClaim("org_id")).isEmpty();
    }

    @Test
    void resolvesTheAuthenticationOnceItIsSet() {
        Authentication authentication = new TestingAuthenticationToken("someone", "n/a");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        assertThat(SecurityUtils.getCurrentAuthentication()).contains(authentication);
    }

    @Test
    void resolvesThePrincipalWhenItIsASecurityPrincipal() {
        SecurityPrincipal principal = principal(42L);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, "n/a", principal.getAuthorities()));

        assertThat(SecurityUtils.getCurrentPrincipal()).contains(principal);
        assertThat(SecurityUtils.getCurrentUserId()).contains(42L);
    }

    @Test
    void doesNotResolveAPrincipalOfAnUnrelatedType() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("plain-string", "n/a"));

        assertThat(SecurityUtils.getCurrentPrincipal()).isEmpty();
        assertThat(SecurityUtils.getCurrentUserId()).isEmpty();
    }

    @Test
    void resolvesAClaimFromJwtAuthenticationDetails() {
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("someone", "n/a");
        authentication.setDetails(new JwtAuthenticationDetails(null, Map.of("org_id", "acme")));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        Optional<Object> claim = SecurityUtils.getCurrentClaim("org_id");

        assertThat(claim).contains("acme");
    }

    @Test
    void doesNotResolveAClaimWhenDetailsAreNotJwtAuthenticationDetails() {
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("someone", "n/a");
        authentication.setDetails("plain-details");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        assertThat(SecurityUtils.getCurrentClaim("org_id")).isEmpty();
    }
}
