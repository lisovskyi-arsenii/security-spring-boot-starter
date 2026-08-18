package com.lisovskyi.security.autoconfigure.security;

import com.lisovskyi.security.autoconfigure.cookie.CsrfCookieFilter;
import com.lisovskyi.security.autoconfigure.security.jwt.JwtAuthFilter;
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
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.HandlerExceptionResolver;

@AutoConfiguration
@EnableWebSecurity
@EnableMethodSecurity
public class DefaultSecurityAutoConfiguration {
    private final SecurityProperties securityProperties;
    private final JwtAuthFilter jwtAuthFilter;
    private final CsrfCookieFilter csrfCookieFilter;
    private final ObjectProvider<SecurityFilterChainCustomizer> chainCustomizerProvider;

    private final HandlerExceptionResolver handlerExceptionResolver;

    public DefaultSecurityAutoConfiguration(
            SecurityProperties securityProperties,
            ObjectProvider<JwtAuthFilter> jwtAuthFilterProvider,
            ObjectProvider<CsrfCookieFilter> csrfCookieFilterProvider,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver,
            ObjectProvider<SecurityFilterChainCustomizer> chainCustomizerProvider
    ) {
        this.securityProperties = securityProperties;
        this.jwtAuthFilter = jwtAuthFilterProvider.getIfAvailable();
        this.csrfCookieFilter = csrfCookieFilterProvider.getIfAvailable();
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.chainCustomizerProvider = chainCustomizerProvider;
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
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
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
                );

        SecurityFilterChainCustomizer chainCustomizer = chainCustomizerProvider.getIfAvailable();
        if (chainCustomizer != null) {
            chainCustomizer.customize(http);
        }

        // A customizer may raise sessionCreationPolicy above STATELESS for its own
        // reasons (e.g. oauth2Login() needs a session-backed AuthorizationRequestRepository
        // for the redirect round-trip) - that alone makes Spring Security default the
        // SecurityContext itself to HttpSessionSecurityContextRepository for the *whole*
        // chain, not just the OAuth2 endpoints. That silently drags CsrfAuthenticationStrategy
        // into play: every JWT-cookie-authenticated request that doesn't carry a session
        // cookie looks like "first login in a new session" to SessionManagementFilter, so it
        // rotates (deletes, since this runs after CsrfFilter/CsrfCookieFilter already wrote
        // the response's Set-Cookie) the CSRF cookie on requests that never touched OAuth2 at
        // all. Pin the security-context repository back to request-scoped explicitly, as the
        // last word after any customizer - this is a different repository interface from
        // OAuth2Login's own authorization-request storage, so it doesn't affect that flow.
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

        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());

        return http.build();
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
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) {
        return config.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(UserDetailsService.class)
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);

        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }
}
