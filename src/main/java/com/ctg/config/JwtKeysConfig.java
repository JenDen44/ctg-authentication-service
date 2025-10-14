package com.ctg.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

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
        private String cookieDomain;
        private String jwksPath;
    }

    @Data
    public static class Keys {
        private String activeKid;
        private List<KeyItem> items;

        @Data
        public static class KeyItem {
            private String kid;
            private String privatePem;
            private String publicPem;
        }
    }
}
