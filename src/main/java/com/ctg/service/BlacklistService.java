package com.ctg.service;

import java.time.Duration;

public interface BlacklistService {
    void blacklist(String jti, Duration ttl);
    boolean isBlacklisted(String jti);
}
