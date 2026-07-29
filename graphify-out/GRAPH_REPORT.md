# Graph Report - lisovskyi-security-starter  (2026-07-26)

## Corpus Check
- 25 files · ~3,477 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 142 nodes · 345 edges · 14 communities (12 shown, 2 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 19 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]

## God Nodes (most connected - your core abstractions)
1. `JwtService` - 14 edges
2. `JwtBlacklistService` - 12 edges
3. `SecurityPrincipal` - 11 edges
4. `JwtAuthFilter` - 10 edges
5. `CookieService` - 9 edges
6. `SecurityAutoConfiguration` - 7 edges
7. `CsrfCookieFilter` - 7 edges
8. `DefaultSecurityAutoConfiguration` - 7 edges
9. `InMemoryJwtBlacklistService` - 7 edges
10. `UserByIdDetailsService` - 7 edges

## Surprising Connections (you probably didn't know these)
- `InMemoryJwtBlacklistService` --implements--> `JwtBlacklistService`  [EXTRACTED]
  security-starter-autoconfigure/src/main/java/com/lisovskyi/security/autoconfigure/security/jwt/InMemoryJwtBlacklistService.java → security-starter-core/src/main/java/com/lisovskyi/security/autoconfigure/security/jwt/JwtBlacklistService.java
- `RedisJwtBlacklistService` --implements--> `JwtBlacklistService`  [EXTRACTED]
  security-starter-autoconfigure/src/main/java/com/lisovskyi/security/autoconfigure/security/jwt/RedisJwtBlacklistService.java → security-starter-core/src/main/java/com/lisovskyi/security/autoconfigure/security/jwt/JwtBlacklistService.java

## Import Cycles
- None detected.

## Communities (14 total, 2 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.13
Nodes (17): AuthenticationConfiguration, AuthenticationManager, AuthenticationProvider, SecurityAutoConfiguration, Bean, ConditionalOnBean, ConditionalOnClass, ConditionalOnMissingBean (+9 more)

### Community 1 - "Community 1"
Cohesion: 0.29
Nodes (4): List, ObjectProvider, SecurityFilterChainCustomizer, SecurityProperties

### Community 2 - "Community 2"
Cohesion: 0.16
Nodes (12): Claims, Collection, Date, Function, GrantedAuthority, JwtService, Map, Object (+4 more)

### Community 3 - "Community 3"
Cohesion: 0.18
Nodes (9): Boolean, expireAfterCreate(), expireAfterRead(), expireAfterUpdate(), InMemoryJwtBlacklistService, JwtBlacklistService, RedisJwtBlacklistService, Override (+1 more)

### Community 5 - "Community 5"
Cohesion: 0.27
Nodes (6): CookieService, CsrfCookieFilter, FilterChain, HttpServletResponse, OncePerRequestFilter, SecurityMdcFilter

### Community 12 - "Community 12"
Cohesion: 0.29
Nodes (6): HandlerExceptionResolver, HttpServletRequest, JwtAuthFilter, UserByIdDetailsService, UserDetails, UserDetailsService

### Community 13 - "Community 13"
Cohesion: 0.46
Nodes (3): Authentication, Optional, SecurityUtils

## Knowledge Gaps
- **2 isolated node(s):** `graphify`, `Workflow: graphify`
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `JwtService` connect `Community 2` to `Community 0`, `Community 12`?**
  _High betweenness centrality (0.105) - this node is a cross-community bridge._
- **Why does `JwtBlacklistService` connect `Community 3` to `Community 0`, `Community 12`?**
  _High betweenness centrality (0.089) - this node is a cross-community bridge._
- **Why does `JwtAuthFilter` connect `Community 12` to `Community 0`, `Community 1`, `Community 5`?**
  _High betweenness centrality (0.074) - this node is a cross-community bridge._
- **What connects `graphify`, `Workflow: graphify` to the rest of the system?**
  _2 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.12834224598930483 - nodes in this community are weakly interconnected._