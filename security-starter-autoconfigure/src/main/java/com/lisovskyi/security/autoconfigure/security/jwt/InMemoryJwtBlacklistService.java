package com.lisovskyi.security.autoconfigure.security.jwt;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.index.qual.NonNegative;
import org.jspecify.annotations.NonNull;

import java.util.concurrent.TimeUnit;

@Slf4j
public class InMemoryJwtBlacklistService implements JwtBlacklistService {
    private final Cache<String, Boolean> blacklist = Caffeine.newBuilder()
            .expireAfter(new Expiry<String, Boolean>() {
                @Override
                public long expireAfterCreate(@NonNull String key, @NonNull Boolean value, long currentTime) {
                    return Long.MAX_VALUE;
                }
                @Override
                public long expireAfterUpdate(@NonNull String key, @NonNull Boolean value, long currentTime, @NonNegative long currentDuration) {
                    return currentDuration;
                }
                @Override
                public long expireAfterRead(@NonNull String key, @NonNull Boolean value, long currentTime, @NonNegative long currentDuration) {
                    return currentDuration;
                }
            })
            .build();

    public InMemoryJwtBlacklistService() {
        log.warn("Redis is not detected. Using InMemoryJwtBlacklistService. This is not suitable for distributed/microservice environments.");
    }

    @Override
    public void addToBlacklist(String jwt, long expirationTimeInMillis) {
        long ttlMillis = expirationTimeInMillis - System.currentTimeMillis();
        if (ttlMillis > 0) {
            String key = hashToken(jwt);
            blacklist.policy().expireVariably().ifPresentOrElse(
                    policy -> policy.put(key, Boolean.TRUE, ttlMillis, TimeUnit.MILLISECONDS),
                    () -> blacklist.put(key, Boolean.TRUE)
            );
        }
    }

    @Override
    public boolean isBlacklisted(String jwt) {
        return blacklist.getIfPresent(hashToken(jwt)) != null;
    }

    @Override
    public void removeFromBlacklist(String jwt) {
        blacklist.invalidate(hashToken(jwt));
    }

    @Override
    public void clearBlacklist() {
        blacklist.invalidateAll();
    }
}
