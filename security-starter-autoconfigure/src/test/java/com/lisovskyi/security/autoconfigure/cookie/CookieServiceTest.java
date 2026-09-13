package com.lisovskyi.security.autoconfigure.cookie;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.lang.reflect.Field;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class CookieServiceTest {

    private CookieProperties properties;
    private CookieService cookieService;

    @BeforeEach
    void setUp() throws Exception {
        properties = new CookieProperties();
        cookieService = new CookieService(properties);

        // @Value("${server.servlet.context-path:}") is only resolved when the bean is created
        // by Spring; outside a Spring context it defaults to "", matching the property's default.
        Field contextPath = CookieService.class.getDeclaredField("contextPath");
        contextPath.setAccessible(true);
        contextPath.set(cookieService, "");
    }

    @Test
    void setAccessTokenCookieWritesASetCookieHeaderWithTheConfiguredName() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieService.setAccessTokenCookie(response, "token-value");

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains(properties.getAccessTokenName() + "=token-value");
        assertThat(header).contains("Path=" + properties.getAccessTokenPath());
        assertThat(header).contains("HttpOnly");
        assertThat(header).contains("Secure");
    }

    @Test
    void clearAccessTokenCookieSetsAnEmptyValueAndZeroMaxAge() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieService.clearAccessTokenCookie(response);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains(properties.getAccessTokenName() + "=");
        assertThat(header).contains("Max-Age=0");
    }

    @Test
    void setRefreshTokenCookieUsesTheRefreshTokenPathAndName() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieService.setRefreshTokenCookie(response, "refresh-value");

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains(properties.getRefreshTokenName() + "=refresh-value");
        assertThat(header).contains("Path=" + properties.getRefreshTokenPath());
    }

    @Test
    void getAccessTokenCookieReadsBackAPreviouslySetCookie() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new jakarta.servlet.http.Cookie(properties.getAccessTokenName(), "abc123"));

        Optional<String> value = cookieService.getAccessTokenCookie(request);

        assertThat(value).contains("abc123");
    }

    @Test
    void getAccessTokenCookieIsEmptyWhenNoCookiesArePresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThat(cookieService.getAccessTokenCookie(request)).isEmpty();
    }

    @Test
    void getRefreshTokenCookieIsEmptyWhenOnlyAnUnrelatedCookieIsPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new jakarta.servlet.http.Cookie("some_other_cookie", "value"));

        assertThat(cookieService.getRefreshTokenCookie(request)).isEmpty();
    }
}
