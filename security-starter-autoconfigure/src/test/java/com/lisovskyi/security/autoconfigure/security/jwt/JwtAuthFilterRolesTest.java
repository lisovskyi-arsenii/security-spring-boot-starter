package com.lisovskyi.security.autoconfigure.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.lisovskyi.security.autoconfigure.cookie.CookieProperties;
import com.lisovskyi.security.autoconfigure.cookie.CookieService;
import com.lisovskyi.security.autoconfigure.security.SecurityPrincipal;
import com.lisovskyi.security.autoconfigure.security.UserByIdDetailsService;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * JwtAuthFilter with a REAL JwtService (signed token, real parsing) - what matters here is which
 * authorities end up on the authentication, depending on {@code roles-from-claims}.
 */
class JwtAuthFilterRolesTest {

    private static JwtService jwtService;

    @BeforeAll
    static void createJwtService() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        JwtProperties properties = new JwtProperties();
        properties.setPrivateKey(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        properties.setIssuer("roles-test");
        properties.setAccessTokenExpiration(900_000L);
        jwtService = new JwtService(properties);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    // A principal that, like core-service's, knows only the id: its role is a fixed "USER".
    private final UserByIdDetailsService idOnlyPrincipal = userId -> new SecurityPrincipal() {
        @Override
        public Long getId() {
            return userId;
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
        public @NonNull String getUsername() {
            return userId.toString();
        }
    };

    private JwtAuthFilter filter(boolean rolesFromClaims) {
        return new JwtAuthFilter(
                jwtService,
                new CookieService(new CookieProperties()),
                idOnlyPrincipal,
                new InMemoryJwtBlacklistService(),
                (request, response, handler, ex) -> {
                    throw new AssertionError("the request must not fail: " + ex);
                },
                rolesFromClaims);
    }

    private Authentication authenticate(JwtAuthFilter filter, Map<String, Object> claims) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + jwtService.generateToken("42", claims));
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private static List<String> names(Authentication authentication) {
        return authentication.getAuthorities().stream().map(Object::toString).toList();
    }

    @Test
    void withTheFlagOn_theRolesOfTheTokenBecomeAuthorities_besidesThePrincipalsOwn() throws Exception {
        Authentication authentication =
                authenticate(filter(true), Map.of("roles", List.of("OWNER", "ADMIN")));

        assertThat(names(authentication)).containsExactlyInAnyOrder("ROLE_USER", "ROLE_OWNER", "ROLE_ADMIN");
    }

    @Test
    void withTheFlagOff_theRolesClaimIsIgnored_asBefore() throws Exception {
        Authentication authentication = authenticate(filter(false), Map.of("roles", List.of("OWNER", "ADMIN")));

        assertThat(names(authentication)).containsExactly("ROLE_USER");
    }

    @Test
    void theOriginalFiveArgumentConstructor_keepsTheOldBehaviour() throws Exception {
        JwtAuthFilter legacy = new JwtAuthFilter(
                jwtService,
                new CookieService(new CookieProperties()),
                idOnlyPrincipal,
                new InMemoryJwtBlacklistService(),
                (request, response, handler, ex) -> null);

        assertThat(names(authenticate(legacy, Map.of("roles", List.of("OWNER"))))).containsExactly("ROLE_USER");
    }

    @Test
    void aTokenWithoutRoles_stillAuthenticates_withTheDefaultAuthority() throws Exception {
        assertThat(names(authenticate(filter(true), Map.of()))).containsExactly("ROLE_USER");
    }

    @Test
    void aMalformedRolesClaim_doesNotBreakAuthentication() throws Exception {
        assertThat(names(authenticate(filter(true), Map.of("roles", "OWNER")))).containsExactly("ROLE_USER");
    }

    @Test
    void theClaimsStayAvailableThroughTheAuthenticationDetails() throws Exception {
        Authentication authentication = authenticate(filter(true), Map.of("roles", List.of("OWNER"), "org_id", 7));

        JwtAuthenticationDetails details = (JwtAuthenticationDetails) authentication.getDetails();
        assertThat(details.claim("org_id")).isEqualTo(7);
    }
}
