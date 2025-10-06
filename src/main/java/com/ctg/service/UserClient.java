package com.ctg.service;

import com.ctg.domain.UserRecord;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class UserClient {

    private final WebClient userServiceClient;

    public Mono<UserRecord> findByEmail(String email) {
        return userServiceClient.get()
                .uri(uri -> uri.path("/internal/users/by-email").queryParam("email", email).build())
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(UserRecord.class);
    }

    public Mono<Void> incrementTokenVersion(Long userId) {
        return userServiceClient.post()
                .uri("/internal/users/{id}/token-version/increment", userId)
                .retrieve()
                .bodyToMono(Void.class);
    }
}
