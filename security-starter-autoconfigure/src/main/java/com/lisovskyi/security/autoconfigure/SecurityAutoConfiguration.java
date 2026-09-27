package com.lisovskyi.security.autoconfigure;

import com.lisovskyi.security.autoconfigure.cookie.CookieProperties;
import com.lisovskyi.security.autoconfigure.cookie.CsrfCookieFilter;
import com.lisovskyi.security.autoconfigure.security.DefaultSecurityAutoConfiguration;
import com.lisovskyi.security.autoconfigure.security.SecurityMdcFilter;
import com.lisovskyi.security.autoconfigure.security.SecurityProperties;
import com.lisovskyi.security.autoconfigure.security.UserByIdDetailsService;
import com.lisovskyi.security.autoconfigure.security.jwt.*;
import com.lisovskyi.security.autoconfigure.cookie.CookieService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Redis/in-memory {@code JwtBlacklistService} selection lives in
 * {@link JwtBlacklistAutoConfiguration}, not here - see its Javadoc for why that
 * split matters for {@code @AutoConfigureAfter} ordering.
 */
@Configuration
@EnableConfigurationProperties({CookieProperties.class, JwtProperties.class, SecurityProperties.class})
@Import({DefaultSecurityAutoConfiguration.class})
@ConditionalOnProperty(prefix = "app.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SecurityAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SecurityAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(final JwtProperties jwtProperties) {
        return new JwtService(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("app.jwt.private-key")
    public JwksController jwksController(final JwtService jwtService) {
        return new JwksController(jwtService);
    }

    @Bean
    @ConditionalOnMissingBean
    public OpaqueTokenService opaqueTokenService() {
        return new OpaqueTokenService();
    }

    @Bean
    @ConditionalOnMissingBean
    public CookieService cookieService(final CookieProperties cookieProperties) {
        return new CookieService(cookieProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(UserByIdDetailsService.class)
    public JwtAuthFilter jwtAuthFilter(
            final JwtService jwtService,
            final CookieService cookieService,
            final UserByIdDetailsService userDetailsService,
            final JwtBlacklistService jwtBlacklistService,
            @Qualifier("handlerExceptionResolver") final HandlerExceptionResolver handlerExceptionResolver
    ) {
        return new JwtAuthFilter(jwtService, cookieService, userDetailsService, jwtBlacklistService, handlerExceptionResolver);
    }

    /**
     * Exists purely to log a warning: with no {@link UserByIdDetailsService} bean,
     * {@code jwtAuthFilter} above is never created (its {@code @ConditionalOnBean}
     * fails), so JWT authentication is silently skipped and every request reaches
     * {@code anyRequest().authenticated()} unauthenticated.
     */
    @Bean
    @ConditionalOnMissingBean(UserByIdDetailsService.class)
    public JwtAuthDisabledNotice jwtAuthDisabledNotice() {
        log.warn("No UserByIdDetailsService bean found - JwtAuthFilter will not be registered. "
                + "JWT authentication is disabled; every request will be treated as unauthenticated "
                + "unless another mechanism populates the SecurityContext.");
        return new JwtAuthDisabledNotice();
    }

    /** Marker type for {@link #jwtAuthDisabledNotice()} - carries no state or behaviour. */
    public static final class JwtAuthDisabledNotice {
    }

    @Bean
    @ConditionalOnMissingBean
    public CsrfCookieFilter csrfCookieFilter() {
        return new CsrfCookieFilter();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityMdcFilter securityMdcFilter() {
        return new SecurityMdcFilter();
    }
}
