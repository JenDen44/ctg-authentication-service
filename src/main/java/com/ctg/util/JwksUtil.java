package com.ctg.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

public class JwksUtil {

    public static String buildJwks(Map<String, RSAPublicKey> pubKeysByKid) {
        List<JWK> keys = pubKeysByKid.entrySet().stream()
                .map(e -> new RSAKey.Builder(e.getValue())
                        .keyUse(KeyUse.SIGNATURE)
                        .algorithm(JWSAlgorithm.RS256)
                        .keyID(e.getKey())
                        .build())
                .map(k -> (JWK) k)
                .toList();
        JWKSet jwkSet = new JWKSet(keys);

        return JSONObjectUtils.toJSONString(jwkSet.toJSONObject());
    }
}
