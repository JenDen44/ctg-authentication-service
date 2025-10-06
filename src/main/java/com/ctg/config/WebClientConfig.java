package com.ctg.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient userServiceClient(
            @Value("${user-service.base-url}") String baseUrl,
            @Value("${user-service.internal-secret}") String shared
    ) {
        return WebClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("X-Internal-Secret", shared)
                .filter(ExchangeFilterFunction.ofRequestProcessor(req -> {
                    return Mono.just(req);
                }))
                .build();
    }
}
