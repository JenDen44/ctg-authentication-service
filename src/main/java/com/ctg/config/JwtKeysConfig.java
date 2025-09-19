package com.ctg.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "auth")
@Data
public class JwtKeysConfig {
    private Jwt jwt = new Jwt();
    private Keys keys = new Keys();

    @Data
    public static class Jwt {
        private String issuer;
        private String audience;
        private String accessTtl;
        private String refreshTtl;
        private String cookieName;
        private String jwksPath;
    }

    @Data
    public static class Keys {
        private String privatePemLocation;
        private String publicPemLocation;
        private String keyId;
    }
}
