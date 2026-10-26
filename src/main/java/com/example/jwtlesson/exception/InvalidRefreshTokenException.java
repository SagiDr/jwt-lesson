package com.example.jwtlesson.exception;

// Unknown, expired, already used or revoked refresh token -> 401 (see GlobalExceptionHandler)
public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException() {
        super("Invalid or expired refresh token");
    }
}
