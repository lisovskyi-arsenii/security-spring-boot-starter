package com.lisovskyi.security.autoconfigure.security;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityPropertiesTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void includesDefaultPublicPathsByDefault() {
        SecurityProperties properties = new SecurityProperties();

        assertThat(properties.getPublicPaths()).contains("/auth/**", "/error/**", "/.well-known/jwks.json");
    }

    @Test
    void mergesUserConfiguredPathsWithTheDefaultsWithoutDuplicates() {
        SecurityProperties properties = new SecurityProperties();
        properties.setPublicPaths(List.of("/custom/**", "/auth/**"));

        assertThat(properties.getPublicPaths())
                .contains("/custom/**", "/auth/**", "/error/**")
                .doesNotHaveDuplicates();
    }

    @Test
    void excludesDefaultPathsWhenDisabled() {
        SecurityProperties properties = new SecurityProperties();
        properties.setIncludeDefaultPublicPaths(false);
        properties.setPublicPaths(List.of("/custom/**"));

        assertThat(properties.getPublicPaths()).containsExactly("/custom/**");
    }

    @Test
    void returnsOnlyDefaultsWhenNoCustomPathsAndDefaultsEnabled() {
        SecurityProperties properties = new SecurityProperties();
        properties.setPublicPaths(null);

        assertThat(properties.getPublicPaths()).isNotEmpty();
    }

    @Test
    void returnsEmptyWhenDefaultsDisabledAndNoCustomPathsConfigured() {
        SecurityProperties properties = new SecurityProperties();
        properties.setIncludeDefaultPublicPaths(false);
        properties.setPublicPaths(null);

        assertThat(properties.getPublicPaths()).isEmpty();
    }

    @Test
    void defaultsMatchTheDocumentedOutOfTheBoxBehaviour() {
        SecurityProperties properties = new SecurityProperties();

        assertThat(properties.getAllowedOrigins()).containsExactly("*");
        assertThat(properties.getAllowedHeaders()).containsExactly("*");
        assertThat(properties.getAllowedMethods()).contains("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
        assertThat(properties.isAllowCredentials()).isFalse();
        assertThat(properties.getBcryptStrength()).isNull();
    }

    @Test
    void acceptsANullBcryptStrength() {
        SecurityProperties properties = new SecurityProperties();

        assertThat(validator.validate(properties)).isEmpty();
    }

    @Test
    void acceptsBcryptStrengthAtTheBoundaries() {
        SecurityProperties properties = new SecurityProperties();

        properties.setBcryptStrength(4);
        assertThat(validator.validate(properties)).isEmpty();

        properties.setBcryptStrength(31);
        assertThat(validator.validate(properties)).isEmpty();
    }

    @Test
    void rejectsABcryptStrengthBelowTheMinimum() {
        SecurityProperties properties = new SecurityProperties();
        properties.setBcryptStrength(3);

        Set<ConstraintViolation<SecurityProperties>> violations = validator.validate(properties);

        assertThat(violations).anySatisfy(v -> assertThat(v.getPropertyPath().toString()).isEqualTo("bcryptStrength"));
    }

    @Test
    void rejectsABcryptStrengthAboveTheMaximum() {
        SecurityProperties properties = new SecurityProperties();
        properties.setBcryptStrength(32);

        Set<ConstraintViolation<SecurityProperties>> violations = validator.validate(properties);

        assertThat(violations).anySatisfy(v -> assertThat(v.getPropertyPath().toString()).isEqualTo("bcryptStrength"));
    }
}
