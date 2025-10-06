package com.ctg.controller;

import com.ctg.dto.LoginRequest;
import com.ctg.dto.TokenResponse;
import com.ctg.dto.ValidateResponse;
import com.ctg.service.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public Mono<ResponseEntity<TokenResponse>> login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public Mono<ResponseEntity<TokenResponse>> refresh(@CookieValue(name = "${auth.jwt.cookie-name}", required = false)
                                                           String refreshCookie,
                                                       @RequestHeader(value = "Cookie", required = false)
                                                            String rawCookieHeader) {
        return authService.refresh(refreshCookie, rawCookieHeader);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader(value="Authorization", required=false) String authHeader,
                                       @CookieValue(name = "${auth.jwt.cookie-name}", required = false) String refreshCookie,
                                       @RequestHeader(value = "Cookie", required = false) String rawCookieHeader) {
        return authService.logout(authHeader, refreshCookie, rawCookieHeader);
    }

    @PostMapping("/logout-all")
    public Mono<ResponseEntity<Void>> logoutAll(@RequestHeader("Authorization") String authHeader) {
        return authService.logoutAll(authHeader);
    }

    @GetMapping("/validate")
    public ResponseEntity<ValidateResponse> validate(@RequestHeader("Authorization") String authHeader) {
        return authService.validate(authHeader);
    }
}
