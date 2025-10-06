package com.ctg.service;

import com.ctg.domain.Pair;
import com.ctg.domain.Role;

public interface RefreshTokenService {
    Pair mint(Long userId, String email, Role role);
    Pair rotate(String oldRefreshJwt);
    void revoke(String refreshJwt);
    void revokeAll(Long userId);
}
