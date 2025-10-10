package com.ctg.service;

import com.ctg.config.JwtKeysConfig;
import com.ctg.constants.JwtConstants;
import com.ctg.domain.Role;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.Key;
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
                .setHeaderParam("kid", keys.getActiveKid())
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
                .signWith(keys.getActivePrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public String createRefresh(Long userId, String email, Role role, String familyId, String jti, Duration ttl) {
        Instant now = Instant.now();
        Instant exp = now.plus(ttl);
        return Jwts.builder()
                .setHeaderParam("kid", keys.getActiveKid())
                .setIssuer(keysConfig.getJwt().getIssuer())
                .setSubject(userId.toString())
                .claim(JwtConstants.CLAIM_EMAIL, email)
                .claim(JwtConstants.CLAIM_ROLE, role.name())
                .claim(JwtConstants.CLAIM_TYP, JwtConstants.TYP_REFRESH)
                .claim(JwtConstants.CLAIM_REFRESH_FAMILY_ID, familyId)
                .setId(jti)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(keys.getActivePrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    private SigningKeyResolverAdapter resolver = new SigningKeyResolverAdapter() {
        @Override
        public Key resolveSigningKey(JwsHeader header, Claims claims) {
            String kid = header.getKeyId();
            RSAPublicKey pub = kid != null ? keys.getPublicKeyByKid(kid) : keys.getActivePublicKey();
            if (pub == null) throw new JwtException("Unknown kid: " + kid);
            return pub;
        }
    };

    Jws<Claims> parseSigned(String jwt) {
        return Jwts.parser()
                .requireIssuer(keysConfig.getJwt().getIssuer())
                .requireAudience(keysConfig.getJwt().getAudience())
                .setAllowedClockSkewSeconds(30)
                .setSigningKeyResolver(resolver)
                .build()
                .parseClaimsJws(jwt);
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

    public RSAPublicKey getPublicKey() { return keys.getActivePublicKey(); }

    public String getKeyId() { return keys.getActiveKid(); }
}
