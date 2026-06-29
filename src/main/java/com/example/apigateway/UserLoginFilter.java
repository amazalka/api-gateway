package com.example.apigateway;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class UserLoginFilter implements GlobalFilter {
    private static final String LOGIN = "preferred_username";
    private static final String USER_LOGIN_HEADER = "X-User-Login";
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(JwtAuthenticationToken.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .map(authentication -> {
                    String login = authentication.getToken().getClaimAsString(LOGIN);
                    if (login == null || login.isBlank()) {
                        return exchange;
                    }
                    ServerHttpRequest request = exchange.getRequest()
                            .mutate()
                            .header(USER_LOGIN_HEADER, login)
                            .build();
                    return exchange.mutate()
                            .request(request)
                            .build();
                })
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }
}
