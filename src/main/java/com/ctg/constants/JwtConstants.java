package com.ctg.constants;

import org.springframework.http.HttpHeaders;

public final class JwtConstants {
    private JwtConstants() {}

    // claims
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_ROLE = "role";
    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_TYP = "typ";
    public static final String CLAIM_TOKEN_VERSION = "tokenVersion";
    public static final String CLAIM_REFRESH_FAMILY_ID = "rfid";

    // typ values
    public static final String TYP_ACCESS = "access";
    public static final String TYP_REFRESH = "refresh";

    // headers
    public static final String HDR_SET_COOKIE = HttpHeaders.SET_COOKIE;
}
