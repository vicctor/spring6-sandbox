package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.stream.Collectors;

//@SpringBootApplication
//@EnableWebFluxSecurity
//@RestController
//@EnableReactiveMethodSecurity
public class WebFluxSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebFluxSecurityApplication.class, args);
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(ex -> ex
                                .pathMatchers("/one").permitAll()
                                .pathMatchers("/two").hasAnyAuthority("authority_1")
                                .pathMatchers("/three/*").access(endingWith3AllowedOnly)
                                .pathMatchers("/three/or/six/*").access(or(endingWith3AllowedOnly, endingWith6AllowedOnly))
                                .pathMatchers("/even/*").hasAnyAuthority("no_odd")
                )
                .authenticationManager(reactiveAuthenticationManager)
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    private <T> ReactiveAuthorizationManager<T> or(ReactiveAuthorizationManager<T>... managers) {
        return (authentication, context) ->
                Flux.merge(
                    Arrays.stream(managers)
                          .map(m -> m.check(authentication, context))
                          .collect(Collectors.toList())
						  )
                .reduce((a, b) -> new AuthorizationDecision(a.isGranted() || b.isGranted()));
    }

    private ReactiveAuthenticationManager reactiveAuthenticationManager = authentication -> Mono.just(
                switch (authentication) {
                    case UsernamePasswordAuthenticationToken a -> getUsernamePasswordAuthenticationToken(a);
                    default -> throw new IllegalStateException("Unexpected value: " + authentication);
                }
        );

    private ReactiveAuthorizationManager<AuthorizationContext> endingWith3AllowedOnly = endingWithAuthorizationConstraint(3);
    private ReactiveAuthorizationManager<AuthorizationContext> endingWith6AllowedOnly = endingWithAuthorizationConstraint(6);

    private ReactiveAuthorizationManager<AuthorizationContext> endingWithAuthorizationConstraint(int with) {
        return (authentication, object) -> authentication.map(a -> new AuthorizationDecision(
                object.getExchange().getRequest().getPath().toString().endsWith("/" + with)
        ));
    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(UsernamePasswordAuthenticationToken a) {
        var password = a.getCredentials().toString().split(",");
        var authorities = Arrays.stream(password).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(a, a.getPrincipal(), authorities);
    }

    @Component("authExpressions")
    public static class WebSecurity {
        public boolean checkIsEven(int value) {
                return value % 2 == 0;
        }
    }

    @GetMapping("one")
    public int one() {
        return 1;
    }

    @GetMapping("two")
    public int two() {
        return 2;
    }

    @GetMapping("three/{value}")
    public int three(@PathVariable("value") int value) {
        return value;
    }

    @GetMapping("three/or/six/{value}")
    public int threeOrSix(@PathVariable("value") int value) {
        return value;
    }

    @GetMapping("even/{value}")
    @PreAuthorize("@authExpressions.checkIsEven(#value)")
    public Mono<Integer> even(@PathVariable("value") int value) {
        return Mono.just(value);
    }
}
