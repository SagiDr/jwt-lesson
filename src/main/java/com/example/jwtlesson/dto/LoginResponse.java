package com.example.jwtlesson.dto;

import java.util.List;

public record LoginResponse(
        String token,              // access token (JWT, "type": "access") - 15 min, sent as "Authorization: Bearer ..."
        String tokenType,          // "Bearer"
        long expiresInMs,
        String refreshToken,       // refresh token (JWT, "type": "refresh") - 7 days, ONLY for POST /api/auth/refresh
        long refreshExpiresInMs,
        String username,
        List<String> roles) {
}
