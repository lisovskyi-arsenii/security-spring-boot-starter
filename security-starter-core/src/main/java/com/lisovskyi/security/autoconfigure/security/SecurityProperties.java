package com.lisovskyi.security.autoconfigure.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    private static final List<String> DEFAULT_PUBLIC_PATHS = List.of(
            "/auth/**",
            "/error/**",
            "/swagger-ui/**",
            "/v3/api-docs/**"
    );

    private List<String> allowedOrigins = List.of("*");
    private List<String> allowedMethods = List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
    private List<String> allowedHeaders = List.of("*");

    private List<String> publicPaths = new ArrayList<>();
    private boolean includeDefaultPublicPaths = true;
    private boolean allowCredentials = false;

    public List<String> getPublicPaths() {
        Set<String> combined = new LinkedHashSet<>();
        if (includeDefaultPublicPaths) {
            combined.addAll(DEFAULT_PUBLIC_PATHS);
        }
        if (publicPaths != null) {
            combined.addAll(publicPaths);
        }
        return new ArrayList<>(combined);
    }
}
