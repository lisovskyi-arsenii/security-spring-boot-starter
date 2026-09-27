package com.lisovskyi.security.autoconfigure.security;

import com.lisovskyi.security.autoconfigure.cookie.CookieProperties;
import com.lisovskyi.security.autoconfigure.cookie.CsrfCookieFilter;
import com.lisovskyi.security.autoconfigure.security.jwt.JwtAuthFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.lang.reflect.Field;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultSecurityAutoConfigurationTest {

    private static final ObjectProvider<JwtAuthFilter> NO_JWT_AUTH_FILTER = providerOf(null);
    private static final ObjectProvider<CsrfCookieFilter> NO_CSRF_COOKIE_FILTER = providerOf(null);
    private static final HandlerExceptionResolver NO_OP_EXCEPTION_RESOLVER =
            (request, response, handler, ex) -> null;

    @Test
    void wiresACustomSecurityMdcFilterBeanInsteadOfCreatingItsOwn() throws Exception {
        SecurityMdcFilter customFilter = new SecurityMdcFilter();

        DefaultSecurityAutoConfiguration configuration = new DefaultSecurityAutoConfiguration(
                new SecurityProperties(),
                NO_JWT_AUTH_FILTER,
                NO_CSRF_COOKIE_FILTER,
                providerOf(customFilter),
                NO_OP_EXCEPTION_RESOLVER,
                List.of(),
                new CookieProperties()
        );

        assertThat(securityMdcFilterField(configuration)).isSameAs(customFilter);
    }

    @Test
    void leavesSecurityMdcFilterNullWhenNoBeanIsAvailable() throws Exception {
        DefaultSecurityAutoConfiguration configuration = new DefaultSecurityAutoConfiguration(
                new SecurityProperties(),
                NO_JWT_AUTH_FILTER,
                NO_CSRF_COOKIE_FILTER,
                providerOf(null),
                NO_OP_EXCEPTION_RESOLVER,
                List.of(),
                new CookieProperties()
        );

        assertThat(securityMdcFilterField(configuration)).isNull();
    }

    private static <T> ObjectProvider<T> providerOf(final T instance) {
        return new ObjectProvider<>() {
            @Override
            public T getIfAvailable() {
                return instance;
            }
        };
    }

    private SecurityMdcFilter securityMdcFilterField(DefaultSecurityAutoConfiguration configuration) throws Exception {
        Field field = DefaultSecurityAutoConfiguration.class.getDeclaredField("securityMdcFilter");
        field.setAccessible(true);
        return (SecurityMdcFilter) field.get(configuration);
    }
}
