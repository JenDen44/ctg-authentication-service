package com.ctg.service;

import com.ctg.config.JwtKeysConfig;
import com.ctg.constants.JwtConstants;
import com.ctg.domain.UserRecord;
import com.ctg.dto.TokenResponse;
import com.ctg.util.TokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final JwtKeysConfig cfg;
    private final TokenUtil tokenUtil;

    @Override
    public ResponseEntity<TokenResponse> issueTokens(UserRecord user) {
        Duration accessTtl = Duration.parse(cfg.getJwt().getAccessTtl());
        String access = jwtService.createAccess(user.getId(), user.getEmail(), user.getRole(), user.getTokenVersion(), accessTtl);

        var pair = refreshTokenService.mint(user.getId(), user.getEmail(), user.getRole());
        ResponseCookie cookie = tokenUtil.buildRefreshCookie(pair.jwt(), true);

        return ResponseEntity.ok()
                .header(JwtConstants.HDR_SET_COOKIE, cookie.toString())
                .body(TokenResponse.builder()
                        .tokenType("Bearer")
                        .accessToken(access)
                        .expiresIn(accessTtl.toSeconds())
                        .build());
    }

}
