package com.ctg.service;

import com.ctg.domain.UserRecord;
import com.ctg.dto.TokenResponse;
import org.springframework.http.ResponseEntity;

public interface TokenService {
     ResponseEntity<TokenResponse> issueTokens(UserRecord user);
}
