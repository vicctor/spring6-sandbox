package com.example.demo;

import jakarta.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class DemoAppSecurityConfig {
    @Bean
    public org.springframework.security.web.SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(ex -> ex
                        .requestMatchers("/one").permitAll()
                        .requestMatchers("/two").hasAnyAuthority("authority_1")
                        .requestMatchers("/three/*").access(endingWith3AllowedOnly)
                        .requestMatchers("/three/or/six/*").access(AuthorizationManagers.anyOf(endingWith3AllowedOnly, endingWith6AllowedOnly))
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
}
