package com.ctg.service;

import com.ctg.config.JwtKeysConfig;
import com.ctg.constants.JwtConstants;
import com.ctg.domain.Pair;
import com.ctg.domain.RefreshToken;
import com.ctg.domain.Role;
import com.ctg.dto.RefreshTokenDto;
import com.ctg.exception.AuthException;
import com.ctg.repository.RefreshTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {
    private final RefreshTokenRepository repo;
    private final JwtService jwtService;
    private final JwtKeysConfig cfg;

    public Pair mint(Long userId, String email, Role role) {
        String familyId = UUID.randomUUID().toString();
        String jti = UUID.randomUUID().toString();
        Duration ttl = Duration.parse(cfg.getJwt().getRefreshTtl());

        RefreshToken token = build(userId, email, role, familyId, ttl, jti);
        repo.save(token, ttl);
        String jwt = jwtService.createRefresh(userId, email, role, familyId, jti, ttl);

        return new Pair(jwt, token);
    }

    public Pair rotate(String oldRefreshJwt) {
        RefreshTokenDto old = parseOldToken(oldRefreshJwt);

        Long userId = old.getUserId();
        String email = old.getEmail();
        String familyId = old.getFamilyId();
        Role role = old.getRole();
        String oldJti = old.getOldJti();

        RefreshToken existing = validateAndFindExistingToken(oldJti, userId);

        String newJti = UUID.randomUUID().toString();
        Duration ttl = Duration.parse(cfg.getJwt().getRefreshTtl());
        RefreshToken next = build(userId, email, role, familyId, ttl, newJti);

        existing.setRevoked(true);
        existing.setReplacedBy(newJti);
        repo.update(existing);
        repo.save(next, ttl);

        String jwt = jwtService.createRefresh(userId, email, role, familyId, newJti, ttl);
        return new Pair(jwt, next);
    }


    public void revoke(String refreshJwt) {
        Jws<Claims> jws = jwtService.parseSigned(refreshJwt);
        String jti = jws.getPayload().getId();
        repo.revoke(jti);
    }

    public void revokeAll(Long userId) {
        repo.revokeAll(userId);
    }

    private RefreshToken build(Long userId, String email, Role role, String familyId, Duration ttl, String newJti) {
        Instant now = Instant.now();

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


    private RefreshTokenDto parseOldToken(String oldRefreshJwt) {
        Claims claims = jwtService.parseRefreshClaims(oldRefreshJwt);

        String oldJti = claims.getId();
        String familyId = claims.get(JwtConstants.CLAIM_REFRESH_FAMILY_ID, String.class);
        Long userId = Long.parseLong(claims.getSubject());
        String email = claims.get(JwtConstants.CLAIM_EMAIL, String.class);
        Role role = Role.valueOf(claims.get(JwtConstants.CLAIM_ROLE, String.class));

        return RefreshTokenDto.builder()
                .oldJti(oldJti)
                .familyId(familyId)
                .email(email)
                .userId(userId)
                .role(role)
                .build();
    }

    private RefreshToken validateAndFindExistingToken(String oldJti, Long userId) {
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
        return existing;
    }
}