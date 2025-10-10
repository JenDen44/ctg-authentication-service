package com.ctg.controller;

import com.ctg.service.KeyProvider;
import com.ctg.util.JwksUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final KeyProvider keyProvider;

    @GetMapping(value = "/.well-known/jwks.json", produces=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> jwks() {
        String body = JwksUtil.buildJwks(keyProvider.getAllPublicKeys());

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(body);
    }
}
