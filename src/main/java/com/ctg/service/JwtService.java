package com.ctg.service;

import com.ctg.config.JwtKeysConfig;
import com.ctg.constants.JwtConstants;
import com.ctg.domain.Role;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final KeyProvider keys;
    private final JwtKeysConfig keysConfig;

    public String createAccess(Long userId, String email, Role role, int tokenVersion, Duration ttl) {
        Instant now = Instant.now();
        Instant exp = now.plus(ttl);
        return Jwts.builder()
                .setHeaderParam("kid", keys.getKeyId())
                .setIssuer(keysConfig.getJwt().getIssuer())
                .setAudience(keysConfig.getJwt().getAudience())
                .setSubject(userId.toString())
                .claim(JwtConstants.CLAIM_EMAIL, email)
                .claim(JwtConstants.CLAIM_ROLE, role.name())
                .claim(JwtConstants.CLAIM_TOKEN_VERSION, tokenVersion)
                .claim(JwtConstants.CLAIM_TYP, JwtConstants.TYP_ACCESS)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(keys.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public String createRefresh(Long userId, String email, Role role, String familyId, String jti, Duration ttl) {
        Instant now = Instant.now();
        Instant exp = now.plus(ttl);
        return Jwts.builder()
                .setHeaderParam("kid", keys.getKeyId())
                .setIssuer(keysConfig.getJwt().getIssuer())
                .setSubject(userId.toString())
                .claim(JwtConstants.CLAIM_EMAIL, email)
                .claim(JwtConstants.CLAIM_ROLE, role.name())
                .claim(JwtConstants.CLAIM_TYP, JwtConstants.TYP_REFRESH)
                .claim(JwtConstants.CLAIM_REFRESH_FAMILY_ID, familyId)
                .setId(jti)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(keys.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public Jws<Claims> parseSigned(String jwt) {
        return Jwts.parser()
                .verifyWith(keys.getPublicKey())
                .build()
                .parseSignedClaims(jwt);
    }

    public Claims parseClaims(String jwt) {
        return parseSigned(jwt).getPayload();
    }

    public Claims parseAccessClaims(String jwt) {
        Claims claims = parseClaims(jwt);
        String typ = claims.get(JwtConstants.CLAIM_TYP, String.class);
        if (!JwtConstants.TYP_ACCESS.equals(typ)) {
            throw new JwtException("Not an access token");
        }
        return claims;
    }

    public Claims parseRefreshClaims(String jwt) {
        Claims claims = parseClaims(jwt);
        String typ = claims.get(JwtConstants.CLAIM_TYP, String.class);
        if (!JwtConstants.TYP_REFRESH.equals(typ)) {
            throw new JwtException("Not a refresh token");
        }
        return claims;
    }

    public RSAPublicKey getPublicKey() { return keys.getPublicKey(); }

    public String getKeyId() { return keys.getKeyId(); }
}
