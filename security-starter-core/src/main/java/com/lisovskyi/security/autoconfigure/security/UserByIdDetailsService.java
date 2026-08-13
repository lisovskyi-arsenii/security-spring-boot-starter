package com.lisovskyi.security.autoconfigure.security;

public interface UserByIdDetailsService {
    SecurityPrincipal loadUserById(Long userId);
}
