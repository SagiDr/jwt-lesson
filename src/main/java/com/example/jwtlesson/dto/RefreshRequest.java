package com.example.jwtlesson.dto;

import jakarta.validation.constraints.NotBlank;

// Body of POST /api/auth/refresh and POST /api/auth/logout
public record RefreshRequest(
        @NotBlank String refreshToken) {
}
