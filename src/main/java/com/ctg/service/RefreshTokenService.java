package com.ctg.service;

import com.ctg.config.JwtKeysConfig;
import com.ctg.domain.RefreshToken;
import com.ctg.domain.Role;
import com.ctg.exception.AuthException;
import com.ctg.repository.RefreshTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository repo;
    private final JwtService jwtService;
    private final JwtKeysConfig cfg;
    public static record Pair(String jwt, RefreshToken stored) {}

    public Pair mint(Long userId, String email, Role role) {
        String familyId = UUID.randomUUID().toString();
        String jti = UUID.randomUUID().toString();
        Duration ttl = Duration.parse(cfg.getJwt().getRefreshTtl());

        RefreshToken rt = build(userId, email, role, familyId, ttl);
        repo.save(rt, ttl);
        String jwt = jwtService.createRefresh(userId, email, role, familyId, jti, ttl);

        return new Pair(jwt, rt);
    }

    public Pair rotate(String oldRefreshJwt) throws AuthException {
        Jws<Claims> jws = Jwts.parser().setSigningKey(jwtService.getPublicKey()).build().parseClaimsJws(oldRefreshJwt);
        Claims c = jws.getBody();

        if (!"refresh".equals(c.get("typ", String.class))) {
            throw new AuthException("Not a refresh token");
        }

        String oldJti = c.getId();
        String familyId = c.get("rfid", String.class);
        Long userId = Long.parseLong(c.getSubject());
        String email = c.get("email", String.class);
        Role role = Role.valueOf(c.get("role", String.class));

        Optional<RefreshToken> existingOpt = repo.find(oldJti);

        if (existingOpt.isEmpty()) {
            repo.revokeAll(userId);
            throw new AuthException("Refresh reuse detected");
        }

        RefreshToken existing = existingOpt.get();

        if (existing.isRevoked()) {
            repo.revokeAll(userId);
            throw new AuthException("Refresh token revoked");
        }

        Duration ttl = Duration.parse(cfg.getJwt().getRefreshTtl());

        RefreshToken next = build(userId, email, role, familyId, ttl);

        String newJti = next.getJti();
        existing.setRevoked(true);
        existing.setReplacedBy(newJti);
        repo.update(existing);
        repo.save(next, ttl);

        String jwt = jwtService.createRefresh(userId, email, role, familyId, newJti, ttl);

        return new Pair(jwt, next);
    }

    public void revoke(String refreshJwt) {
        Jws<Claims> jws = Jwts.parser().setSigningKey(jwtService.getPublicKey()).build().parseClaimsJws(refreshJwt);
        String jti = jws.getBody().getId();
        repo.revoke(jti);
    }

    public void revokeAll(Long userId) {
        repo.revokeAll(userId);
    }

    private RefreshToken build(Long userId, String email, Role role, String familyId, Duration ttl) {
        Instant now = Instant.now();
        String newJti = UUID.randomUUID().toString();

        return RefreshToken.builder()
                .jti(newJti)
                .userId(userId)
                .email(email)
                .role(role)
                .familyId(familyId)
                .issuedAt(now)
                .expiresAt(now.plus(ttl))
                .revoked(false)
                .build();
    }
}