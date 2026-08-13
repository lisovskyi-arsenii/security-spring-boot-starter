package com.lisovskyi.security.autoconfigure.security.jwt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public interface JwtBlacklistService {
    void addToBlacklist(String jwt, long expirationTimeInMillis);

    boolean isBlacklisted(String jwt);

    void removeFromBlacklist(String jwt);

    void clearBlacklist();

    default String hashToken(String jwt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(jwt.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
