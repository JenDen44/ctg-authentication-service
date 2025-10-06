package com.ctg.controller;

import com.ctg.service.JwtService;
import com.ctg.util.JwksUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final JwtService jwtService;

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public String jwks() {
        return JwksUtil.buildJwks(jwtService.getKeyId(), jwtService.getPublicKey());
    }
}
