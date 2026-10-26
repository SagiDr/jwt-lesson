package com.example.jwtlesson.service;

import com.example.jwtlesson.entity.RefreshToken;
import com.example.jwtlesson.entity.User;
import com.example.jwtlesson.exception.InvalidRefreshTokenException;
import com.example.jwtlesson.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Refresh tokens: long-lived (7 days), stored in the DB, so - unlike a JWT - they CAN be revoked.
 * Rotation: every refresh token works only once; each refresh returns a new one.
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-expiration-ms}")
    private long refreshExpirationMs;

    /** Creates a refresh token for the user. Returns the RAW token - the only time it exists outside the client. */
    @Transactional
    public String create(User user) {
        byte[] bytes = new byte[32];                 // 256 random bits - impossible to guess
        RANDOM.nextBytes(bytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        refreshTokenRepository.save(RefreshToken.builder()
                .tokenHash(hash(rawToken))           // store the HASH only
                .user(user)
                .expiresAt(Instant.now().plusMillis(refreshExpirationMs))
                .build());
        return rawToken;
    }

    /**
     * Validates the token and marks it as used. Returns its owner.
     * Throws InvalidRefreshTokenException if the token is unknown, expired, already used or revoked.
     * noRollbackFor: when reuse is detected, the "revoke all" must be saved even though we throw.
     */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public User consume(String rawToken) {
        RefreshToken token = refreshTokenRepository.findByTokenHash(hash(rawToken))
                .orElseThrow(InvalidRefreshTokenException::new);

        if (token.isRevoked()) {
            // A token that was already used came back -> someone copied it. Log the user out everywhere.
            refreshTokenRepository.revokeAllByUser(token.getUser());
            throw new InvalidRefreshTokenException();
        }
        if (token.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidRefreshTokenException();
        }

        token.setRevoked(true);                      // rotation: this token will not work again
        return token.getUser();
    }

    /** Logout: the token stops working. An unknown token is ignored - nothing to reveal. */
    @Transactional
    public void revoke(String rawToken) {
        refreshTokenRepository.findByTokenHash(hash(rawToken))
                .ifPresent(token -> token.setRevoked(true));
    }

    public long getRefreshExpirationMs() {
        return refreshExpirationMs;
    }

    // SHA-256 and not BCrypt: the token is already 256 random bits (nothing to brute-force),
    // and we must FIND it by its value - BCrypt's random salt makes a lookup impossible.
    private static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
