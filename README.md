# lisovskyi-security-starter

![Java](https://img.shields.io/badge/Java-25-orange?logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.1.0-brightgreen?logo=springboot)
![Spring Security](https://img.shields.io/badge/Spring%20Security-BOM--managed-brightgreen?logo=springsecurity)
![Version](https://img.shields.io/badge/version-0.1.2-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)

A production-grade Spring Boot security auto-configuration library. It ships stateless JWT authentication, CSRF protection, CORS configuration, cookie management, and a JWT token blacklist — all wired automatically, fully overridable, and split into a clean two-module architecture.

---

## Project Overview

Securing a Spring Boot microservice requires wiring together many concerns: JWT parsing and validation, stateless session management, CSRF token handling, CORS policies, password encoding, exception delegation, and logout-safe token revocation. Doing this per-service leads to copy-paste security code that is easy to get wrong.

`lisovskyi-security-starter` encapsulates all of these concerns in a single dependency. The consumer service only needs to implement two interfaces (`SecurityPrincipal` and `UserByIdDetailsService`) and provide a signing key — the rest is handled automatically.

### Module breakdown

| Module | Artifact ID | Purpose |
|---|---|---|
| `security-starter-core` | `security-starter-core` | Public API: interfaces, annotations, properties, utilities |
| `security-starter-autoconfigure` | `security-starter-autoconfigure` | Auto-configuration: `SecurityFilterChain`, `JwtService`, `CookieService`, blacklist implementations |
| Root project | `lisovskyi-security-starter` | Aggregator that re-exports both modules as a single dependency |

---

## Features

- ✅ **Stateless JWT authentication** — `JwtAuthFilter` intercepts every request, extracts the token from the `Authorization: Bearer …` header or an HTTP-only cookie, validates it, and populates the `SecurityContextHolder`.
- ✅ **Dual token strategy** — `JwtService` generates short-lived access tokens (15 min default) and long-lived refresh tokens (7 days default).
- ✅ **JWT blacklist** — `JwtBlacklistService` interface with two auto-configured implementations:
  - `RedisJwtBlacklistService` — activated automatically when a `StringRedisTemplate` bean is present (recommended for distributed/microservice environments).
  - `InMemoryJwtBlacklistService` — Caffeine-backed fallback for single-node deployments (logs a warning at startup).
  - Token hashes (SHA-256) are stored instead of raw tokens.
- ✅ **Cookie management** — `CookieService` sets and clears `HttpOnly`, `Secure`, `SameSite` cookies for access and refresh tokens with configurable paths and TTLs.
- ✅ **CSRF protection** — cookie-based CSRF token repository (`CookieCsrfTokenRepository`) with public paths excluded automatically.
- ✅ **CORS configuration** — configurable allowed origins, methods, headers, and credentials.
- ✅ **Security headers** — `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'self'`, HSTS with subdomains enabled.
- ✅ **MDC tracing** — `SecurityMdcFilter` populates MDC after authentication for structured log correlation.
- ✅ **`@CurrentUser` annotation** — injects the current `SecurityPrincipal` directly into controller method parameters (returns `null` for anonymous users).
- ✅ **`SecurityUtils`** — static helpers to retrieve the current authentication, principal, or user ID from the `SecurityContextHolder`.
- ✅ **`SecurityFilterChainCustomizer`** — functional interface to extend the default `SecurityFilterChain` without replacing it entirely.
- ✅ **Fully conditional** — every bean is `@ConditionalOnMissingBean`, so any part can be replaced without touching the starter.

---

## Technologies Used

| Technology | Version |
|---|---|
| Java | 25 (minimum: 21) |
| Spring Boot BOM | 4.1.0 |
| Spring Security | (BOM-managed) |
| Spring Web | (BOM-managed) |
| Spring Data Redis | (BOM-managed, optional) |
| jjwt-api / jjwt-impl / jjwt-jackson | 0.13.0 |
| Caffeine | 3.2.4 |
| Lombok | 1.18.46 |
| Gradle | (wrapper included) |

> **Java version note:** The library is compiled with JDK 25. Consumer services must use JDK **21 or later** (the minimum LTS version compatible with Spring Boot 4.x).

---

## Project Structure

```
lisovskyi-security-starter/
├── security-starter-core/                              # Public API module
│   └── src/main/java/com/lisovskyi/security/autoconfigure/
│       ├── cookie/
│       │   └── CookieProperties.java                  # app.cookie.* configuration
│       └── security/
│           ├── SecurityPrincipal.java                 # Interface: UserDetails + getId() + getRole()
│           ├── SecurityProperties.java                # app.security.* configuration (CORS, public paths)
│           ├── SecurityFilterChainCustomizer.java     # Hook to extend the default SecurityFilterChain
│           ├── SecurityUtils.java                     # Static helpers: getCurrentPrincipal(), getCurrentUserId()
│           ├── UserByIdDetailsService.java            # Interface: loadUserById(String userId)
│           ├── annotation/
│           │   └── CurrentUser.java                   # Parameter annotation for @AuthenticationPrincipal
│           └── jwt/
│               ├── JwtProperties.java                 # app.jwt.* configuration (key, expiry, issuer)
│               └── JwtBlacklistService.java           # Blacklist interface with SHA-256 hash helper
│
├── security-starter-autoconfigure/                    # Implementation module
│   └── src/main/java/com/lisovskyi/security/autoconfigure/
│       ├── SecurityAutoConfiguration.java             # Root @Configuration: wires all beans
│       ├── cookie/
│       │   ├── CookieService.java                     # Sets/clears access and refresh token cookies
│       │   └── CsrfCookieFilter.java                  # Refreshes CSRF cookie on each response
│       └── security/
│           ├── DefaultSecurityAutoConfiguration.java  # SecurityFilterChain, CORS, PasswordEncoder, AuthManager
│           ├── SecurityMdcFilter.java                 # Adds userId to MDC after JWT authentication
│           └── jwt/
│               ├── JwtService.java                    # Token generation and validation (JJWT)
│               ├── JwtAuthFilter.java                 # OncePerRequestFilter — header + cookie extraction
│               ├── InMemoryJwtBlacklistService.java   # Caffeine-backed blacklist (single-node)
│               └── RedisJwtBlacklistService.java      # Redis-backed blacklist (distributed)
│
├── build.gradle.kts                                   # Root build — aggregates submodules
└── settings.gradle.kts                                # Includes security-starter-core and security-starter-autoconfigure
```

---

## Prerequisites

- Java **21+** (compiled against JDK 25)
- Gradle (wrapper `gradlew` / `gradlew.bat` is bundled)
- A Spring Boot **4.1.0** consumer project with `spring-boot-starter-security` and `spring-boot-starter-web`
- (Optional) Redis for distributed JWT blacklisting

---

## Installation

Build and publish all modules to the local Maven repository:

```bash
./gradlew publishToMavenLocal
```

### Gradle (Kotlin DSL)

```kotlin
// build.gradle.kts
repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("com.lisovskyi:lisovskyi-security-starter:0.1.2")
}
```

### Maven

```xml
<!-- pom.xml -->
<repositories>
  <repository>
    <id>local</id>
    <url>file://${user.home}/.m2/repository</url>
  </repository>
</repositories>

<dependencies>
  <dependency>
    <groupId>com.lisovskyi</groupId>
    <artifactId>lisovskyi-security-starter</artifactId>
    <version>0.1.2</version>
  </dependency>
</dependencies>
```

> **Note:** If you only need the public API types (interfaces, annotations, properties) without the auto-configuration, depend on `security-starter-core:0.1.2` instead.

---

## Configuration

### Required

```yaml
# application.yml
app:
  jwt:
    signing-key: "<your-base64-encoded-HS256-key>"  # REQUIRED — no default
```

### Full reference

```yaml
app:
  security:
    enabled: true                          # default: true — set to false to disable the entire starter
    allowed-origins:
      - "*"                                # default: ["*"]
    allowed-methods:
      - GET
      - POST
      - PUT
      - PATCH
      - DELETE
      - OPTIONS
    allowed-headers:
      - "*"
    allow-credentials: false               # default: false
    include-default-public-paths: true     # default: true — includes /auth/**, /error/**, /swagger-ui/**, /v3/api-docs/**
    public-paths:                          # additional public paths (merged with defaults when include-default-public-paths=true)
      - "/actuator/health"

  jwt:
    signing-key: "<base64-encoded-key>"    # REQUIRED
    access-token-expiration: 900000        # default: 900000 ms (15 minutes)
    refresh-token-expiration: 604800000    # default: 604800000 ms (7 days)
    issuer: "lisovskyi-security-service"   # default

  cookie:
    access-token-name: "access_token"      # default
    refresh-token-name: "refresh_token"    # default
    access-token-path: "/"                 # default
    refresh-token-path: "/auth/refresh"    # default
    access-token-max-age: 900              # default: seconds
    refresh-token-max-age: 604800          # default: seconds
    domain:                                # optional — leave blank for current domain
    same-site: "Strict"                    # default
    secure: true                           # default
    http-only: true                        # default
```

---

## Usage Examples

### 1. Implement `SecurityPrincipal`

Your `User` entity (or a dedicated `UserDetailsImpl`) must implement `SecurityPrincipal`:

```java
@Entity
public class User implements SecurityPrincipal {

    private UUID id;
    private String email;
    private String password;
    private String role;      // e.g. "ADMIN" or "ROLE_USER"

    @Override
    public Object getId() { return id; }

    @Override
    public String getRole() { return role; }

    @Override
    public String getUsername() { return email; }

    @Override
    public String getPassword() { return password; }
}
```

### 2. Implement `UserByIdDetailsService`

```java
@Service
@RequiredArgsConstructor
public class UserService implements UserByIdDetailsService {

    private final UserRepository userRepository;

    @Override
    public SecurityPrincipal loadUserById(String userId) {
        return userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userId));
    }
}
```

### 3. Issue tokens on login

```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final JwtService jwtService;
    private final CookieService cookieService;

    @PostMapping("/login")
    public ResponseEntity<Void> login(@RequestBody LoginRequest request,
                                      HttpServletResponse response) {
        User user = userService.authenticate(request);

        cookieService.setAccessTokenCookie(response, jwtService.generateToken(user));
        cookieService.setRefreshTokenCookie(response, jwtService.generateRefreshToken(user));

        return ResponseEntity.ok().build();
    }
}
```

### 4. Access the current user in a controller

```java
@GetMapping("/me")
public ResponseEntity<ProfileDto> getProfile(@CurrentUser User user) {
    return ResponseEntity.ok(profileService.getProfile(user));
}
```

### 5. Revoke a token on logout

```java
@PostMapping("/logout")
public ResponseEntity<Void> logout(@CurrentUser User user,
                                   HttpServletRequest request,
                                   HttpServletResponse response,
                                   JwtBlacklistService blacklistService,
                                   JwtService jwtService) {
    String token = extractTokenFromRequest(request);
    Date expiration = jwtService.extractExpiration(token);
    blacklistService.addToBlacklist(token, expiration.getTime());

    cookieService.clearAccessTokenCookie(response);
    cookieService.clearRefreshTokenCookie(response);

    return ResponseEntity.noContent().build();
}
```

### 6. Extend the `SecurityFilterChain`

```java
@Bean
public SecurityFilterChainCustomizer myCustomizer() {
    return http -> http.authorizeHttpRequests(auth ->
            auth.requestMatchers("/admin/**").hasRole("ADMIN")
    );
}
```

---

## Known Limitations

- **`InMemoryJwtBlacklistService` is not distributed** — it stores revoked tokens in a local JVM heap. In a multi-instance deployment, a token revoked on instance A is still accepted on instance B. Always provision Redis in production microservice environments (a `StringRedisTemplate` bean is all that is required for the Redis implementation to activate automatically).
- **JWT signing key must be Base64-encoded** — the `app.jwt.signing-key` value must be a Base64-encoded HMAC-SHA256 key of at least 256 bits (32 bytes). An unencoded or weak key will cause an `io.jsonwebtoken.security.WeakKeyException` at startup.
- **`JwtAuthFilter` requires `UserByIdDetailsService`** — if no bean implementing `UserByIdDetailsService` is present, the filter is not registered (guarded by `@ConditionalOnBean`). This means JWT authentication will be silently skipped. Provide the implementation to activate the filter.
- **`SecurityFilterChainCustomizer` is single-bean** — only one customizer bean is supported. If you need multiple customizations, combine them in a single lambda or define a composite.
- **Java version coupling** — compiled against JDK 25, targeting Spring Boot 4.1.0. If your consumer project uses an older BOM, version conflicts in Spring Security or JJWT transitive dependencies may arise.

---

## Testing

```bash
./gradlew test
```

---

## Contributing

Contributions are welcome!

1. Fork the repository and create your feature branch from `main`.
2. Make sure the project builds and tests pass: `./gradlew build`.
3. For security-related changes, include a brief threat-model justification in the PR description.
4. Keep code style consistent with the existing conventions (Lombok, `@ConditionalOnMissingBean` for all beans).
5. Open a pull request describing what you changed and why.

---

## License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](LICENSE) file for details.

Key points of Apache 2.0:
- ✅ Free to use, modify, and distribute
- ✅ Can be used in commercial and proprietary projects
- ✅ Patent grant — contributors grant users a license to any patents covering the contribution
- ✅ Must preserve copyright and license notices
- ✅ Changes to the source must be stated
