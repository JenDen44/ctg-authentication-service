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
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeyProvider {
    private final ResourceLoader resourceLoader;
    private final JwtKeysConfig cfg;

    @Getter
    private String activeKid;
    private final Map<String, KeyPairHolder> keys = new LinkedHashMap<>();

    @PostConstruct
    public void init() {
        try {
            var kcfg = cfg.getKeys();
            if (kcfg == null || kcfg.getItems() == null || kcfg.getItems().isEmpty()) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair keyPair = generator.generateKeyPair();
                String kid = "dev-generated";
                this.activeKid = kid;
                keys.put(kid, new KeyPairHolder((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate()));
                log.warn("Generated ephemeral RSA keypair for DEV. kid={}", kid);
            } else {
                this.activeKid = Objects.requireNonNull(kcfg.getActiveKid(), "auth.keys.active-kid must be set");
                for (var item : kcfg.getItems()) {
                    RSAPrivateKey priv = loadPrivatePem(item.getPrivatePem());
                    RSAPublicKey pub  = loadPublicPem(item.getPublicPem());

                    if (!pub.getModulus().equals(priv.getModulus())) {
                        throw new IllegalStateException("Public and private key mismatch for kid=" + item.getKid());
                    }

                    keys.put(item.getKid(), new KeyPairHolder(pub, priv));
                    log.info("Loaded PEM key kid={}", item.getKid());
                }
                if (!keys.containsKey(activeKid)) {
                    throw new IllegalStateException("Active kid not found: " + activeKid);
                }
                log.info("Active kid={}", activeKid);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to init keys", e);
        }
    }

    public RSAPrivateKey getActivePrivateKey() {
        return requireHolder(activeKid).privateKey();
    }

    public RSAPublicKey getActivePublicKey() {
        return requireHolder(activeKid).publicKey();
    }

    public RSAPublicKey getPublicKeyByKid(String kid) {
        var holder = keys.get(kid);
        return holder != null ? holder.publicKey() : null;
    }

    public Map<String, RSAPublicKey> getAllPublicKeys() {
        return Collections.unmodifiableMap(
                keys.entrySet().stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                e -> e.getValue().publicKey(),
                                (a, b) -> a,
                                LinkedHashMap::new
                        ))
        );
    }

    private KeyPairHolder requireHolder(String kid) {
        var holder = keys.get(kid);
        if (holder == null) throw new IllegalStateException("Key not found for kid=" + kid);
        return holder;
    }

    private RSAPrivateKey loadPrivatePem(String location) throws Exception {
        Resource res = resourceLoader.getResource(location);
        if (!res.exists()) {
            throw new IllegalStateException("Private key not found at: " + location);
        }
        try (InputStream is = res.getInputStream()) {
            String raw = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            if (raw.contains("BEGIN RSA PRIVATE KEY")) {
                throw new IllegalArgumentException(
                        "Private key is PKCS#1 (-----BEGIN RSA PRIVATE KEY-----). " +
                                "Convert to PKCS#8 with:\n" +
                                "  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rsa_private_pkcs1.pem -out private_pkcs8.pem"
                );
            }
            String pem = raw
                    .replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(pem);
            var spec = new PKCS8EncodedKeySpec(der);
            var kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(spec);
        }
    }

    private RSAPublicKey loadPublicPem(String location) throws Exception {
        Resource res = resourceLoader.getResource(location);
        if (!res.exists()) {
            throw new IllegalStateException("Public key not found at: " + location);
        }
        try (InputStream is = res.getInputStream()) {
            String raw = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            if (!raw.contains("BEGIN PUBLIC KEY")) {
                throw new IllegalArgumentException(
                        "Unsupported public key format. Expected '-----BEGIN PUBLIC KEY-----'."
                );
            }
            String pem = raw
                    .replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(pem);
            var spec = new X509EncodedKeySpec(der);
            var kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(spec);
        }
    }

    private record KeyPairHolder(RSAPublicKey publicKey, RSAPrivateKey privateKey) {}
}
