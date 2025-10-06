package com.ctg.service;

import com.ctg.config.JwtKeysConfig;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeyProvider {
    private final ResourceLoader resourceLoader;
    private final JwtKeysConfig jwtKeysConfig;
    @Getter private RSAPrivateKey privateKey;
    @Getter private RSAPublicKey publicKey;
    @Getter private String keyId;

    @PostConstruct
    public void init() {
        try {
            this.keyId = jwtKeysConfig.getKeys().getKeyId();
            String privLoc = jwtKeysConfig.getKeys().getPrivatePemLocation();
            String pubLoc = jwtKeysConfig.getKeys().getPublicPemLocation();
            if (privLoc != null && !privLoc.isBlank() && pubLoc != null && !pubLoc.isBlank()) {
                this.privateKey = loadPrivatePem(privLoc);
                this.publicKey = loadPublicPem(pubLoc);
                log.info("Loaded RSA keys from PEM. kid={}", keyId);
            } else {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair kp = generator.generateKeyPair();
                this.privateKey = (RSAPrivateKey) kp.getPrivate();
                this.publicKey = (RSAPublicKey) kp.getPublic();
                log.warn("Generated ephemeral RSA keypair for dev use. Provide PEMs for production. kid={}", keyId);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to init keys", e);
        }
    }

    private RSAPrivateKey loadPrivatePem(String location) throws Exception {
        Resource res = resourceLoader.getResource(location);
        try (InputStream is = res.getInputStream()) {
            String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            String base64 = pem.replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(spec);
        }
    }

    private RSAPublicKey loadPublicPem(String location) throws Exception {
        Resource res = resourceLoader.getResource(location);
        try (InputStream is = res.getInputStream()) {
            String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            String base64 = pem.replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(spec);
        }
    }
}
