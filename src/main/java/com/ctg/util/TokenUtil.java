package com.ctg.util;

import com.ctg.config.JwtKeysConfig;
import com.ctg.exception.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class TokenUtil {
    private final JwtKeysConfig cfg;

    public ResponseCookie buildRefreshCookie(String value, boolean set) {
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(cfg.getJwt().getCookieName(), value)
                .httpOnly(true).secure(true).path("/").sameSite("Strict");
        if (cfg.getJwt().getCookieDomain() != null && !cfg.getJwt().getCookieDomain().isBlank()) {
            builder.domain(cfg.getJwt().getCookieDomain());
        }
        if (set) {
            long maxAge = Duration.parse(cfg.getJwt().getRefreshTtl()).toSeconds();
            builder.maxAge(maxAge);
        } else {
            builder.maxAge(0);
        }
        return builder.build();
    }


    public static String extractCookie(String rawCookieHeader, String name) {
        if (rawCookieHeader == null) return null;
        for (String part : rawCookieHeader.split("; ")) {
            if (part.startsWith(name + "=")) return part.substring((name+"=").length());
        }
        return null;
    }

    public String retrieveRefreshToken(String refreshCookie, String rawCookieHeader) {
        System.out.println(refreshCookie + " refreshCookie и rawCookieHeader " + rawCookieHeader);
        String refreshJwt = Optional.ofNullable(refreshCookie)
                .orElseGet(() -> TokenUtil.extractCookie(rawCookieHeader, cfg.getJwt().getCookieName()));
        if (refreshJwt == null || refreshJwt.isBlank()) throw new AuthException("No refresh cookie");

        System.out.println(refreshJwt);
        return refreshJwt;
    }

    public static String retrieveAccessToken(String authHeader) {
        String access = (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : null;
        if (access == null || access.isBlank()) throw new AuthException("No access token");

        return access;
    }
}
