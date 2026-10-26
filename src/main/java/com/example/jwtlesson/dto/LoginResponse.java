package com.example.jwtlesson.dto;

import java.util.List;

public record LoginResponse(
        String token,              // access token (JWT) - short-lived, sent as "Authorization: Bearer ..."
        String tokenType,          // "Bearer"
        long expiresInMs,
        String refreshToken,       // long-lived, used ONLY with POST /api/auth/refresh
        long refreshExpiresInMs,
        String username,
        List<String> roles) {
}
