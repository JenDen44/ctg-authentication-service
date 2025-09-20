package com.ctg.repository;

import com.ctg.domain.RefreshToken;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Repository
@RequiredArgsConstructor
public class RefreshTokenRepository {
    private final RedisTemplate<String, Object> redis;
    private String key(String jti) { return "rt:" + jti; }
    private String userSet(Long userId) { return "user:" + userId + ":rts"; }

    public void save(RefreshToken token, Duration ttl) {
        redis.opsForValue().set(key(token.getJti()), token, ttl);
        SetOperations<String, Object> setOps = redis.opsForSet();
        setOps.add(userSet(token.getUserId()), token.getJti());
        redis.expire(userSet(token.getUserId()), ttl);
    }

    public Optional<RefreshToken> find(String jti) {
        Object obj = redis.opsForValue().get(key(jti));
        return Optional.of((RefreshToken) obj);
    }

    public void update(RefreshToken token) {
        var ttl = Duration.between(Instant.now(), token.getExpiresAt());
        if (!ttl.isNegative()) {
            redis.opsForValue().set(key(token.getJti()), token, ttl);
        } else {
            redis.delete(key(token.getJti()));
        }
    }

    public void revoke(String jti) {
        find(jti).ifPresent(rt -> {
            rt.setRevoked(true);
            update(rt);
            redis.opsForSet().remove(userSet(rt.getUserId()), rt.getJti());
        });
    }

    public Set<String> listUserTokens(Long userId) {
        Set<Object> members = redis.opsForSet().members(userSet(userId));
        Set<String> out = new HashSet<>();
        for (Object o : members) out.add((String) o);

        return out;
    }

    public void revokeAll(Long userId) {
        for (String jti : listUserTokens(userId)) {
            revoke(jti);
        }
        redis.delete(userSet(userId));
    }
}