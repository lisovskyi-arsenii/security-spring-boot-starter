package com.lisovskyi.security.autoconfigure.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

@RequiredArgsConstructor
public class RedisJwtBlacklistService implements JwtBlacklistService {

    private static final String PREFIX = "jwt:blacklist:";
    private static final int BATCH_SIZE = 1000;

    private final StringRedisTemplate redisTemplate;

    @Override
    public void addToBlacklist(final String jwt, long expirationTimeInMillis) {
        long ttl = expirationTimeInMillis - System.currentTimeMillis();
        if (ttl > 0) {
            String key = PREFIX + hashToken(jwt);
            redisTemplate.opsForValue().set(key, "blacklisted", Duration.ofMillis(ttl));
        }
    }

    @Override
    public boolean isBlacklisted(final String jwt) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX + hashToken(jwt)));
    }

    @Override
    public void removeFromBlacklist(final String jwt) {
        redisTemplate.delete(PREFIX + hashToken(jwt));
    }

    @Override
    public void clearBlacklist() {
        ScanOptions options = ScanOptions.scanOptions().match(PREFIX + "*").count(BATCH_SIZE).build();
        Set<String> keys = new HashSet<>();

        try (Cursor<String> cursor = redisTemplate.scan(options)) {
            while (cursor.hasNext()) {
                keys.add(cursor.next());
                if (keys.size() >= BATCH_SIZE) {
                    redisTemplate.delete(keys);
                    keys.clear();
                }
            }
            if (!keys.isEmpty()) {
                redisTemplate.delete(keys);
            }
        }
    }
}
