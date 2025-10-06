package com.ctg.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ValidateResponse {
    private boolean valid;
    private String subject;
    private String email;
    private String role;
    private long exp;
    private String jti;
}
