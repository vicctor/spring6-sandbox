package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.stream.Collectors;

@SpringBootApplication
@EnableWebSecurity
@RestController
@EnableMethodSecurity
public class WebSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebSecurityApplication.class, args);
    }

    @Bean
    public SecurityFilterChain springSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(ex -> ex
                                .requestMatchers("/one").permitAll()
                                .requestMatchers("/two").hasAnyAuthority("authority_1")
                                .requestMatchers("/three/*").access(endingWith3AllowedOnly)
                                .requestMatchers("/three/or/six/*").access(or(endingWith3AllowedOnly, endingWith6AllowedOnly))
                                .requestMatchers("/even/*").hasAnyAuthority("no_odd")
                )
                .authenticationManager(authenticationManager)
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    private AuthenticationManager authenticationManager = authentication ->
            switch (authentication) {
                case UsernamePasswordAuthenticationToken a -> getUsernamePasswordAuthenticationToken(a);
                default -> throw new IllegalStateException("Unexpected value: " + authentication);
            };


    private <T> AuthorizationManager<T> or(AuthorizationManager<T>... managers) {
        return (authentication, context) ->
                Arrays.stream(managers)
                    .map(m -> m.check(authentication, context))
                    .reduce((a, b) -> new AuthorizationDecision(a.isGranted() || b.isGranted()))
                    .orElse(new AuthorizationDecision(false));
    }


    private AuthorizationManager<RequestAuthorizationContext> endingWith3AllowedOnly = endingWithAuthorizationConstraint(3);
    private AuthorizationManager<RequestAuthorizationContext> endingWith6AllowedOnly = endingWithAuthorizationConstraint(6);

    private AuthorizationManager<RequestAuthorizationContext> endingWithAuthorizationConstraint(int with) {
        return (authentication, object) -> new AuthorizationDecision(object.getRequest().getServletPath().endsWith("/" + with));
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
