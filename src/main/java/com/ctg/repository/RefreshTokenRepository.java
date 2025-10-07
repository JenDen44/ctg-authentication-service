package com.ctg.repository;

import com.ctg.domain.RefreshToken;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

@Repository
@RequiredArgsConstructor
public class RefreshTokenRepository {

    @Qualifier("refreshTokenRedisTemplate")
    private final RedisTemplate<String, RefreshToken> refreshTokenRedis;
    private final StringRedisTemplate stringRedis;

    private String key(String jti) { return "rt:" + jti; }

    private String userSet(Long userId) { return "user:" + userId + ":rts"; }

    public void save(RefreshToken token, Duration ttl) {
        refreshTokenRedis.opsForValue().set(key(token.getJti()), token, ttl);
        stringRedis.opsForSet().add(userSet(token.getUserId()), token.getJti());
        stringRedis.expire(userSet(token.getUserId()), ttl);
    }

    public Optional<RefreshToken> find(String jti) {
        if (jti == null || jti.isBlank()) return Optional.empty();
        RefreshToken refreshToken = refreshTokenRedis.opsForValue().get(key(jti));
        return Optional.ofNullable(refreshToken);
    }

    public void update(RefreshToken token) {
        var ttl = Duration.between(Instant.now(), token.getExpiresAt());
        if (!ttl.isNegative()) {
            refreshTokenRedis.opsForValue().set(key(token.getJti()), token, ttl);
            stringRedis.expire(userSet(token.getUserId()), ttl);
        } else {
            refreshTokenRedis.delete(key(token.getJti()));
            stringRedis.opsForSet().remove(userSet(token.getUserId()), token.getJti());
        }
    }

    public void revoke(String jti) {
        find(jti).ifPresent(rt -> {
            rt.setRevoked(true);
            update(rt);
            stringRedis.opsForSet().remove(userSet(rt.getUserId()), rt.getJti());
        });
    }

    public Set<String> listUserTokens(Long userId) {
        Set<String> members = stringRedis.opsForSet().members(userSet(userId));
        return members == null? Collections.emptySet() : members;
    }

    public void revokeAll(Long userId) {
        for (String jti : listUserTokens(userId)) {
            revoke(jti);
        }
        stringRedis.delete(userSet(userId));
    }
}