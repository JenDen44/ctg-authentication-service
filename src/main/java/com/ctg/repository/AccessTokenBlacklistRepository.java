package com.ctg.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;

@Repository
@RequiredArgsConstructor
public class AccessTokenBlacklistRepository {

    private final StringRedisTemplate redis;

    private String key(String jti) { return "at:blacklist:" + jti; }

    public void add(String jti, Duration ttl) {
        redis.opsForValue().set(key(jti), "1", ttl);
    }

    public boolean exists(String jti) {
        return Boolean.TRUE.equals(redis.hasKey(key(jti)));
    }
}
