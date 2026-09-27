package com.lisovskyi.security.autoconfigure.cookie;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CookiePropertiesTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void defaultsAreValid() {
        assertThat(validator.validate(new CookieProperties())).isEmpty();
    }

    @Test
    void acceptsAllSameSiteValuesRegardlessOfCase() {
        CookieProperties properties = new CookieProperties();

        for (String value : new String[] {"Strict", "lax", "NONE"}) {
            properties.setSameSite(value);
            assertThat(validator.validate(properties)).isEmpty();
        }
    }

    @Test
    void rejectsAnInvalidSameSiteValue() {
        CookieProperties properties = new CookieProperties();
        properties.setSameSite("Whatever");

        Set<ConstraintViolation<CookieProperties>> violations = validator.validate(properties);

        assertThat(violations).anySatisfy(v -> assertThat(v.getPropertyPath().toString()).isEqualTo("sameSite"));
    }

    @Test
    void rejectsAnInvalidCsrfSameSiteValue() {
        CookieProperties properties = new CookieProperties();
        properties.setCsrfSameSite("invalid");

        Set<ConstraintViolation<CookieProperties>> violations = validator.validate(properties);

        assertThat(violations).anySatisfy(v -> assertThat(v.getPropertyPath().toString()).isEqualTo("csrfSameSite"));
    }
}
