package com.boris.authentication_server.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity
//                .csrf(csrf -> csrf.ignoringRequestMatchers("/user-auth").disable())  // Disable CSRF for the specified paths
//                .authorizeHttpRequests(r -> r.requestMatchers("/user-auth/login/login").permitAll())
//                .authorizeHttpRequests(r -> r.requestMatchers("/user-auth/sign-in/sign").permitAll())
//                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .oauth2ResourceServer(outh -> outh.authenticationManagerResolver(authManagerResolver()))
//                .cors(c -> c.configurationSource(corsConfigurationSource()));  // Explicitly provide the CORS configuration source
//
//        return httpSecurity.build();
//
//    }
//
//    @Value("${AUTH_SERVER:http://localhost:8080}")
//    private String authServerUrl;
//
//    @Value("${AUTH_SERVER_JWKS:http://localhost:8080/oauth2/jwks}")
//    private String authServerJwksUrl;
//
//    @Bean
//    public JwtIssuerAuthenticationManagerResolver authManagerResolver() {
//        // Create a map to hold the association between JWT issuers and their corresponding AuthenticationManagers
//        Map<String, AuthenticationManager> map = new HashMap<>();
//
//        // Add an entry to the map for Google's JWT issuer, associating it with an AuthenticationManager
////        map.put("https://accounts.google.com", authenticationManager("https://www.googleapis.com/oauth2/v3/certs"));
//        map.put(authServerUrl, authenticationManager(authServerJwksUrl));
//
//        // Create and return a JwtIssuerAuthenticationManagerResolver using the map
//        return new JwtIssuerAuthenticationManagerResolver(map::get);
//    }
//
//    private AuthenticationManager authenticationManager(String jwkSetUri) {
//        System.out.println("Fetching JWK Set from URI: " + jwkSetUri);
//        JwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
//        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
//
//        return new ProviderManager(provider);
//    }
//
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(List.of("https://www.brooks-dusura.uk"));  // Allow only your front-end domain
//        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));  // Allow these HTTP methods
//        configuration.setAllowedHeaders(List.of("*"));  // Allow all headers
//        configuration.setAllowCredentials(true);  // Allow credentials like cookies
//        configuration.setExposedHeaders(List.of("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"));
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);  // Apply CORS to all routes
//        return source;
//    }
//
//    @Bean
//    public WebSecurityCustomizer ignoringCustomizer() {
//        return (web) -> web.ignoring().requestMatchers("/sign-in", "/login", "postgres-console/**");
//    }
//}

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${AUTH_SERVER:http://localhost:8080}")
    private String authServerUrl;

    @Value("${AUTH_SERVER_JWKS:http://localhost:8080/oauth2/jwks}")
    private String authServerJwksUrl;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(csrf -> csrf.ignoringRequestMatchers("/user-auth").disable())  // Disable CSRF for the specified paths
                .authorizeHttpRequests(r -> r.requestMatchers("/user-auth/login/login").permitAll())
                .authorizeHttpRequests(r -> r.requestMatchers("/user-auth/sign-in/sign").permitAll())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(outh -> outh.authenticationManagerResolver(authManagerResolver()))
                .cors(c -> c.configurationSource(corsConfigurationSource()))  // Explicitly provide the CORS configuration source
                .addFilterBefore(new JwtTokenLoggingFilter(), BasicAuthenticationFilter.class);  // Add custom filter

        return httpSecurity.build();
    }

    @Bean
    public JwtIssuerAuthenticationManagerResolver authManagerResolver() {
        Map<String, AuthenticationManager> map = new HashMap<>();
        map.put(authServerUrl, authenticationManager(authServerJwksUrl));
        return new JwtIssuerAuthenticationManagerResolver(map::get);
    }

    private AuthenticationManager authenticationManager(String jwkSetUri) {
        System.out.println("Fetching JWK Set from URI: " + jwkSetUri);
        JwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);

        return new ProviderManager(provider);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("https://www.brooks-dusura.uk"));  // Allow only your front-end domain
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));  // Allow these HTTP methods
        configuration.setAllowedHeaders(List.of("*"));  // Allow all headers
        configuration.setAllowCredentials(true);  // Allow credentials like cookies
        configuration.setExposedHeaders(List.of("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);  // Apply CORS to all routes
        return source;
    }

    @Bean
    public WebSecurityCustomizer ignoringCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/sign-in", "/login", "postgres-console/**");
    }
}

// Custom Filter to log JWT token
@Component
class JwtTokenLoggingFilter extends BasicAuthenticationFilter {

    public JwtTokenLoggingFilter() {
        super(new ProviderManager(List.of()));  // No real authentication needed here
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);  // Remove "Bearer " prefix
            System.out.println("JWT Token: " + token);  // Print the token
        }

        chain.doFilter(request, response);  // Continue with the filter chain
    }
}
