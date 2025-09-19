package com.ctg.service;

import com.ctg.config.JwtKeysConfig;
import com.ctg.domain.Role;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final KeyProvider keys;
    private final JwtKeysConfig keysConfig;

    public String createAccess(UUID userId, String email, Role role, int tokenVersion, Duration ttl) {
        Instant now = Instant.now();
        Instant exp = now.plus(ttl);
        return Jwts.builder()
                .setHeaderParam("kid", keys.getKeyId())
                .setIssuer(keysConfig.getJwt().getIssuer())
                .setAudience(keysConfig.getJwt().getAudience())
                .setSubject(userId.toString())
                .claim("email", email)
                .claim("roles", List.of(role.name()))
                .claim("tokenVersion", tokenVersion)
                .claim("typ", "access")
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(keys.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public String createRefresh(UUID userId, String email, Role role, String familyId, String jti, Duration ttl) {
        Instant now = Instant.now();
        Instant exp = now.plus(ttl);
        return Jwts.builder()
                .setHeaderParam("kid", keys.getKeyId())
                .setIssuer(keysConfig.getJwt().getIssuer())
                .setSubject(userId.toString())
                .claim("email", email)
                .claim("role", role.name())
                .claim("typ", "refresh")
                .claim("rfid", familyId)
                .setId(jti)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(keys.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public RSAPublicKey getPublicKey() { return keys.getPublicKey(); }
    public String getKeyId() { return keys.getKeyId(); }
}
