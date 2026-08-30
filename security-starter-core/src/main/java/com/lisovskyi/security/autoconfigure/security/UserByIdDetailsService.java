package com.lisovskyi.security.autoconfigure.security;

@FunctionalInterface
public interface UserByIdDetailsService {
    SecurityPrincipal loadUserById(Long userId);
}
