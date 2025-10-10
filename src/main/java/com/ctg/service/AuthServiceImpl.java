package com.ctg.service;

import com.ctg.config.JwtKeysConfig;
import com.ctg.constants.JwtConstants;
import com.ctg.domain.UserRecord;
import com.ctg.dto.LoginRequest;
import com.ctg.dto.TokenResponse;
import com.ctg.dto.ValidateResponse;
import com.ctg.exception.AuthException;
import com.ctg.util.TokenUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserClient userClient;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final BlacklistService blacklist;
    private final JwtKeysConfig cfg;
    private final TokenService tokenService;
    private final TokenUtil tokenUtil;
    private final PasswordEncoder encoder;

    @Override
    public Mono<ResponseEntity<TokenResponse>> login(LoginRequest request) {
        String email = request.getEmail() == null ? null : request.getEmail().toLowerCase();
        return userClient.findByEmail(email)
                .switchIfEmpty(Mono.error(new AuthException("Invalid credentials")))
                .map(user -> {
                    verifyPassword(user, request.getPassword());
                    return user;
                })
                .map(tokenService::issueTokens);
    }

    @Override
    public Mono<ResponseEntity<TokenResponse>> refresh(String refreshCookie, String rawCookieHeader) {
        String refreshToken = tokenUtil.retrieveRefreshToken(refreshCookie, rawCookieHeader);
        var rotated = refreshTokenService.rotate(refreshToken);

        Duration accessTtl = Duration.parse(cfg.getJwt().getAccessTtl());
        String access = jwtService.createAccess(
                rotated.stored().getUserId(),
                rotated.stored().getEmail(),
                rotated.stored().getRole(),
                0,
                accessTtl
        );

        ResponseCookie cookie = tokenUtil.buildRefreshCookie(rotated.jwt(), true);

        return Mono.just(ResponseEntity.ok()
                .header(JwtConstants.HDR_SET_COOKIE, cookie.toString())
                .body(TokenResponse.builder()
                        .tokenType("Bearer")
                        .accessToken(access)
                        .expiresIn(accessTtl.toSeconds())
                        .build()));
    }

    @Override
    public ResponseEntity<Void> logout(String authHeader, String refreshCookie, String rawCookieHeader) {
        String access = TokenUtil.retrieveAccessToken(authHeader);
        String refreshToken = tokenUtil.retrieveRefreshToken(refreshCookie, rawCookieHeader);
        try {
            Claims claims = jwtService.parseAccessClaims(access);
            long ttlSec = Math.max(0, claims.getExpiration().toInstant().getEpochSecond() - Instant.now().getEpochSecond());
            if (ttlSec > 0) {
                blacklist.blacklist(claims.getId(), Duration.ofSeconds(ttlSec));
            }
        } catch (Exception e) {
            // Не валим логаут из-за битого access просто продолжаем
            // TODO log
        }

        try {
            refreshTokenService.revoke(refreshToken);
        } catch (Exception e) {
            // TODO log
        }

        ResponseCookie expired = tokenUtil.buildRefreshCookie("", false);
        return ResponseEntity.noContent().header(JwtConstants.HDR_SET_COOKIE, expired.toString()).build();
    }

    @Override
    public Mono<ResponseEntity<Void>> logoutAll(String authHeader) {
        String access = TokenUtil.retrieveAccessToken(authHeader);
        Claims claims = jwtService.parseAccessClaims(access);
        Long userId = Long.parseLong(claims.getSubject());

        refreshTokenService.revokeAll(userId);

        return userClient.incrementTokenVersion(userId)
                .thenReturn(ResponseEntity.noContent().build());
    }

    @Override
    public ResponseEntity<ValidateResponse> validate(String authHeader) {
        String access = TokenUtil.retrieveAccessToken(authHeader);
        Claims claims = jwtService.parseAccessClaims(access);

        String jti = claims.getId();
        if (blacklist.isBlacklisted(jti)) {
            throw new AuthException("Token revoked");
        }

        var response = ValidateResponse.builder()
                .valid(true)
                .subject(claims.getSubject())
                .email(claims.get(JwtConstants.CLAIM_EMAIL, String.class))
                .role(claims.get(JwtConstants.CLAIM_ROLE, String.class))
                .exp(claims.getExpiration().toInstant().getEpochSecond())
                .jti(jti)
                .build();

        return ResponseEntity.ok(response);
    }

    private void verifyPassword(UserRecord user, String raw) {
        if (!encoder.matches(raw, user.getPasswordHash())) throw new AuthException("Invalid credentials");
    }
}
