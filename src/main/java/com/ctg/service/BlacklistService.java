package com.ctg.service;

import com.ctg.repository.AccessTokenBlacklistRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.time.Duration;

@Service
@RequiredArgsConstructor
public class BlacklistService {

    private final AccessTokenBlacklistRepository repo;

    public void blacklist(String jti, Duration ttl) {
        if (jti == null || ttl == null) return;
        repo.add(jti, ttl);
    }

    public boolean isBlacklisted(String jti) {
        return jti != null && repo.exists(jti);
    }
}