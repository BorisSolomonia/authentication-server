package com.boris.authentication_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod; // <-- ADDED: to reference HttpMethod.OPTIONS
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${AUTH_SERVER:https://34.67.92.189:8080}")
    private String authServerUrl;

    @Value("${AUTH_SERVER_JWKS:https://34.67.92.189:8080/oauth2/jwks}")
    private String authServerJwksUrl;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        System.out.println("Configuring Security Filter Chain");

        httpSecurity
                // 1) Enable CORS, using the CORS configuration bean defined below
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // 2) Disable CSRF for /user-auth (or any relevant paths)
                .csrf(csrf -> csrf.ignoringRequestMatchers("/user-auth").disable())
                // 3) Configure which requests are permitted
                .authorizeHttpRequests(auth -> auth
                        // ALLOW all OPTIONS (preflight) requests on every path
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // <-- ADDED

                        // Permit specific endpoints
                        .requestMatchers("/user-auth/login/login", "/user-auth/sign-in/sign", "/actuator/health").permitAll()

                        // Anything else requires authentication
                        .anyRequest().authenticated()
                )
                // 4) Use stateless sessions
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 5) Delegate JWT validation to the custom manager resolver
                .oauth2ResourceServer(oauth -> oauth.authenticationManagerResolver(authManagerResolver()));

        return httpSecurity.build();
    }

    @Bean
    public JwtIssuerAuthenticationManagerResolver authManagerResolver() {
        // Map JWT issuers to AuthenticationManagers
        Map<String, AuthenticationManager> map = new HashMap<>();
        map.put(authServerUrl, authenticationManager(authServerJwksUrl));

        return new JwtIssuerAuthenticationManagerResolver(map::get);
    }

    private AuthenticationManager authenticationManager(String jwkSetUri) {
        System.out.println("Fetching JWK Set from URI: " + jwkSetUri);
        JwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);

        provider.setJwtAuthenticationConverter(jwt -> {
            System.out.println("JWT Token: " + jwt.getTokenValue());
            return new JwtAuthenticationToken(jwt);
        });
        return new ProviderManager(provider);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Allow only your front-end domain
        configuration.setAllowedOrigins(List.of("https://www.brooks-dusura.uk"));
        // Allow typical HTTP methods
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // Allow all headers
        configuration.setAllowedHeaders(List.of("*"));
        // Allow credentials like cookies or auth tokens
        configuration.setAllowCredentials(true);

        // Expose any headers the frontend might need to read, e.g., "Authorization" if you’re returning it
        configuration.setExposedHeaders(List.of("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Apply these rules to all endpoints
        source.registerCorsConfiguration("/**", configuration);

        System.out.println("CORS Configuration Initialized: " + configuration);
        return source;
    }

    @Bean
    public WebSecurityCustomizer ignoringCustomizer() {
        // These endpoints are completely ignored by Spring Security
        return (web) -> web.ignoring().requestMatchers("/sign-in", "/login", "postgres-console/**");
    }
}
