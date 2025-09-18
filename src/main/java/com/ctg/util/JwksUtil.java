package com.ctg.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

public class JwksUtil {

    private static String b64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static Map<String, Object> buildJwk(String kid, RSAPublicKey pub) {
        var n = b64Url(pub.getModulus().toByteArray());
        var e = b64Url(pub.getPublicExponent().toByteArray());
        return Map.of(
                "kty", "RSA",
                "kid", kid,
                "alg", "RS256",
                "use", "sig",
                "n", n.startsWith("AA") ? n.substring(2) : n,
                "e", e
        );
    }

    @SneakyThrows
    public static String buildJwks(String kid, RSAPublicKey pub) {
        Map<String, Object> jwk = buildJwk(kid, pub);
        var set = Map.of("keys", new Object[]{jwk});
        return new ObjectMapper().writeValueAsString(set);
    }
}
