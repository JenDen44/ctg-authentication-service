package com.ctg.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
    private String jti;
    private Long userId;
    private String email;
    private Role role;
    private String familyId;
    private Instant issuedAt;
    private Instant expiresAt;
    private boolean revoked;
    private String replacedBy;
}