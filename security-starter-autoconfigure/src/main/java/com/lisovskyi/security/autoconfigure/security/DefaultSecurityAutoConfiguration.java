package com.lisovskyi.security.autoconfigure.security;

import com.lisovskyi.security.autoconfigure.cookie.CookieProperties;
import com.lisovskyi.security.autoconfigure.cookie.CsrfCookieFilter;
import com.lisovskyi.security.autoconfigure.security.jwt.JwtAuthFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.util.List;

@AutoConfiguration
@EnableWebSecurity
@EnableMethodSecurity
public class DefaultSecurityAutoConfiguration {

    private final SecurityProperties securityProperties;
    private final JwtAuthFilter jwtAuthFilter;
    private final CsrfCookieFilter csrfCookieFilter;
    private final List<SecurityFilterChainCustomizer> chainCustomizers;

    private final HandlerExceptionResolver handlerExceptionResolver;
    private final CookieProperties cookieProperties;

    public DefaultSecurityAutoConfiguration(
            final SecurityProperties securityProperties,
            final ObjectProvider<JwtAuthFilter> jwtAuthFilterProvider,
            final ObjectProvider<CsrfCookieFilter> csrfCookieFilterProvider,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver,
            final List<SecurityFilterChainCustomizer> chainCustomizers,
            final CookieProperties cookieProperties) {
        this.securityProperties = securityProperties;
        this.jwtAuthFilter = jwtAuthFilterProvider.getIfAvailable();
        this.csrfCookieFilter = csrfCookieFilterProvider.getIfAvailable();
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.chainCustomizers = chainCustomizers != null ? chainCustomizers : List.of();
        this.cookieProperties = cookieProperties;
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .xssProtection(HeadersConfigurer.XXssConfig::disable)
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(securityProperties.getPublicPaths().toArray(String[]::new))
                        .csrfTokenRepository(nonDeletingCsrfTokenRepository())
                        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
                )
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exc -> exc
                        .authenticationEntryPoint((request, response, authException) ->
                                handlerExceptionResolver.resolveException(request, response, null, authException))
                        .accessDeniedHandler(((request, response, accessDeniedException) ->
                                handlerExceptionResolver.resolveException(request, response, null, accessDeniedException)))
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(securityProperties.getPublicPaths().toArray(String[]::new)).permitAll()
                        .anyRequest().authenticated()
                );

        for (SecurityFilterChainCustomizer customizer : chainCustomizers) {
            customizer.customize(http);
        }

        // A customizer may raise sessionCreationPolicy above STATELESS for its own
        // reasons (e.g. oauth2Login() needs a session-backed AuthorizationRequestRepository
        // for the redirect round-trip) - that alone makes Spring Security default the
        // SecurityContext itself to HttpSessionSecurityContextRepository for the *whole*
        // chain, not just the OAuth2 endpoints. Pin it back to request-scoped explicitly -
        // this is a different repository interface from OAuth2Login's own authorization-
        // request storage, so it doesn't affect that flow.
        http.securityContext(context -> context.securityContextRepository(new RequestAttributeSecurityContextRepository()));

        if (jwtAuthFilter != null) {
            http.addFilterBefore(
                    jwtAuthFilter,
                    UsernamePasswordAuthenticationFilter.class
            );
            http.addFilterAfter(
                    new SecurityMdcFilter(),
                    JwtAuthFilter.class
            );
        }

        if (csrfCookieFilter != null) {
            http.addFilterAfter(
                    csrfCookieFilter,
                    CsrfFilter.class
            );
        }

        return http.build();
    }

    // Whenever a SecurityFilterChainCustomizer raises sessionCreationPolicy above
    // STATELESS for its own reasons (e.g. oauth2Login() needs a session-backed
    // AuthorizationRequestRepository for the redirect round-trip), SessionManagementFilter
    // stays in the chain and folds CsrfAuthenticationStrategy into the session-management
    // strategy it runs on every request - unconditionally, there's no supported way to
    // opt a chain out of it once csrf() is enabled (verified: neither an explicit
    // sessionAuthenticationStrategy(...) override nor removing SessionManagementConfigurer
    // outright stopped it without breaking something else). On every JWT-cookie-
    // authenticated request - which is every request, since there's no session to
    // remember "already seen" - that strategy treats it as a fresh login and calls
    // saveToken(null, ...) to rotate the CSRF token. Since SessionManagementFilter runs
    // after CsrfFilter/CsrfCookieFilter already wrote this response's real Set-Cookie,
    // "rotate" actually means delete (Max-Age=0), not usefully replace.
    //
    // Fix this at its exact mechanical source instead of fighting the filter chain: a
    // thin CsrfTokenRepository wrapper that ignores saveToken(null, ...) specifically.
    // CsrfCookieFilter already keeps the cookie fresh and valid on every request
    // regardless, so there is nothing this null-token save call ever legitimately needed
    // to do here.
    @SuppressWarnings("java:S3330")
    private CsrfTokenRepository nonDeletingCsrfTokenRepository() {
        CookieCsrfTokenRepository delegate = CookieCsrfTokenRepository.withHttpOnlyFalse();

        delegate.setCookieName(cookieProperties.getCsrfCookieName());
        delegate.setCookieCustomizer(customizer -> {
            customizer
                    .path(cookieProperties.getCsrfCookiePath())
                    .sameSite(cookieProperties.getCsrfSameSite())
                    .secure(cookieProperties.isSecure());

            if (cookieProperties.getCsrfCookieDomain() != null && !cookieProperties.getCsrfCookieDomain().isBlank()) {
                customizer.domain(cookieProperties.getCsrfCookieDomain());
            }
        });

        return new CsrfTokenRepository() {
            @Override
            public @NonNull CsrfToken generateToken(@NonNull final HttpServletRequest request) {
                return delegate.generateToken(request);
            }

            @Override
            public void saveToken(final CsrfToken token, @NonNull final HttpServletRequest request, @NonNull final HttpServletResponse response) {
                if (token == null) {
                    return;
                }
                delegate.saveToken(token, request, response);
            }

            @Override
            public CsrfToken loadToken(@NonNull final HttpServletRequest request) {
                return delegate.loadToken(request);
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(securityProperties.getAllowedOrigins());
        corsConfiguration.setAllowedMethods(securityProperties.getAllowedMethods());
        corsConfiguration.setAllowedHeaders(securityProperties.getAllowedHeaders());
        corsConfiguration.setAllowCredentials(securityProperties.isAllowCredentials());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        Integer strength = securityProperties.getBcryptStrength();
        if (strength != null && strength >= 4 && strength <= 31) {
            return new BCryptPasswordEncoder(strength);
        }
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationManager authenticationManager(final AuthenticationConfiguration config) {
        return config.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(UserDetailsService.class)
    public AuthenticationProvider authenticationProvider(final UserDetailsService userDetailsService, final PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);

        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }
}
