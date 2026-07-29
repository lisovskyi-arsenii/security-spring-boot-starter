package com.lisovskyi.security.autoconfigure;

import com.lisovskyi.security.autoconfigure.cookie.CookieProperties;
import com.lisovskyi.security.autoconfigure.cookie.CsrfCookieFilter;
import com.lisovskyi.security.autoconfigure.security.DefaultSecurityAutoConfiguration;
import com.lisovskyi.security.autoconfigure.security.SecurityProperties;
import com.lisovskyi.security.autoconfigure.security.UserByIdDetailsService;
import com.lisovskyi.security.autoconfigure.security.jwt.*;
import com.lisovskyi.security.autoconfigure.cookie.CookieService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Configuration
@EnableConfigurationProperties({CookieProperties.class, JwtProperties.class, SecurityProperties.class})
@Import({DefaultSecurityAutoConfiguration.class})
@ConditionalOnProperty(prefix = "app.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(JwtProperties jwtProperties) {
        return new JwtService(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public CookieService cookieService(CookieProperties cookieProperties) {
        return new CookieService(cookieProperties);
    }

    @Bean
    @ConditionalOnClass(StringRedisTemplate.class)
    @ConditionalOnBean(StringRedisTemplate.class)
    @ConditionalOnSingleCandidate(StringRedisTemplate.class)
    @ConditionalOnMissingBean(JwtBlacklistService.class)
    public JwtBlacklistService redisJwtBlacklistService(StringRedisTemplate redisTemplate) {
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
            JwtService jwtService,
            UserByIdDetailsService userDetailsService,
            JwtBlacklistService jwtBlacklistService,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver,
            CookieProperties cookieProperties
    ) {
        return new JwtAuthFilter(jwtService, userDetailsService, jwtBlacklistService, handlerExceptionResolver, cookieProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public CsrfCookieFilter csrfCookieFilter() {
        return new CsrfCookieFilter();
    }
}
