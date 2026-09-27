package com.lisovskyi.security.autoconfigure.security.jwt;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnSingleCandidate;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Kept apart from {@code SecurityAutoConfiguration} so that {@code @AutoConfigureAfter}
 * actually applies: Spring Boot only sorts classes that go through the deferred
 * auto-configuration import mechanism, i.e. classes listed directly in
 * {@code AutoConfiguration.imports}. As a nested {@code @Bean} method on a plain
 * {@code @Configuration} class, {@code redisJwtBlacklistService} could be evaluated
 * before {@link DataRedisAutoConfiguration} created its {@code StringRedisTemplate},
 * silently falling back to {@link InMemoryJwtBlacklistService} even with Redis
 * available. Being its own {@code @AutoConfiguration(after = ...)} entry - and listed
 * in {@code AutoConfiguration.imports} - guarantees correct ordering.
 */
@AutoConfiguration(after = DataRedisAutoConfiguration.class)
@ConditionalOnProperty(prefix = "app.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JwtBlacklistAutoConfiguration {

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
}
