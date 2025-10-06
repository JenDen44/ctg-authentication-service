package com.ctg.service;

import com.ctg.dto.LoginRequest;
import com.ctg.dto.TokenResponse;
import com.ctg.dto.ValidateResponse;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

public interface AuthService {
    Mono<ResponseEntity<TokenResponse>> login(LoginRequest request);
    Mono<ResponseEntity<TokenResponse>> refresh(String refreshCookie, String rawCookieHeader);
    ResponseEntity<Void> logout(String authHeader, String refreshCookie, String rawCookieHeader);
    Mono<ResponseEntity<Void>> logoutAll(String authHeader);
    ResponseEntity<ValidateResponse> validate(String authHeader);
}