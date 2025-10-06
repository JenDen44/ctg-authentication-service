package com.ctg.dto;

import com.ctg.domain.Role;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RefreshTokenDto {
    private String oldJti;
    private String familyId;
    private Long userId;
    private String email;
    private Role role;
}
