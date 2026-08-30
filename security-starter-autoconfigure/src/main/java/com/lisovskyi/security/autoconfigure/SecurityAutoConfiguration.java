package com.lisovskyi.security.autoconfigure;

import com.lisovskyi.security.autoconfigure.cookie.CookieProperties;
import com.lisovskyi.security.autoconfigure.cookie.CsrfCookieFilter;
import com.lisovskyi.security.autoconfigure.security.DefaultSecurityAutoConfiguration;
import com.lisovskyi.security.autoconfigure.security.SecurityProperties;
import com.lisovskyi.security.autoconfigure.security.UserByIdDetailsService;
import com.lisovskyi.security.autoconfigure.security.jwt.*;
import com.lisovskyi.security.autoconfigure.cookie.CookieService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * {@code @AutoConfigureAfter(DataRedisAutoConfiguration.class)}: this class is
 * a plain {@code @Configuration} (registered via
 * {@code AutoConfiguration.imports}, not annotated {@code @AutoConfiguration}),
 * so without an explicit ordering constraint its {@code @Bean} methods can be
 * evaluated before Spring Boot's own redis autoconfiguration runs. When that
 * happens, {@code redisJwtBlacklistService}'s {@code @ConditionalOnBean(StringRedisTemplate.class)}
 * sees no candidate yet - even though {@code DataRedisAutoConfiguration} goes on
 * to create one moments later - and the app silently falls back to
 * {@link com.lisovskyi.security.autoconfigure.security.jwt.InMemoryJwtBlacklistService}
 * with a live Redis instance sitting right there unused.
 */
@Configuration
@EnableConfigurationProperties({CookieProperties.class, JwtProperties.class, SecurityProperties.class})
@Import({DefaultSecurityAutoConfiguration.class})
@ConditionalOnProperty(prefix = "app.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@AutoConfigureAfter(DataRedisAutoConfiguration.class)
public class SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(final JwtProperties jwtProperties) {
        return new JwtService(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
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
    @ConditionalOnClass(StringRedisTemplate.class)
    @ConditionalOnBean(StringRedisTemplate.class)
    @ConditionalOnSingleCandidate(StringRedisTemplate.class)
    @ConditionalOnMissingBean(JwtBlacklistService.class)
    public JwtBlacklistService redisJwtBlacklistService(final StringRedisTemplate redisTemplate) {
        return new RedisJwtBlacklistService(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean(JwtBlacklistService.class)
    public JwtBlacklistService inMemoryJwtBlacklistService() {
        return new InMemoryJwtBlacklistService();
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

    @Bean
    @ConditionalOnMissingBean
    public CsrfCookieFilter csrfCookieFilter() {
        return new CsrfCookieFilter();
    }
}
