package com.example.jwtlesson.service;

import com.example.jwtlesson.entity.RefreshToken;
import com.example.jwtlesson.entity.User;
import com.example.jwtlesson.exception.InvalidRefreshTokenException;
import com.example.jwtlesson.repository.RefreshTokenRepository;
import com.example.jwtlesson.security.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Refresh tokens are JWTs (7 days). A pure JWT cannot be revoked, so each one also gets a row
 * in the DB (by its "jti"): that is what allows logout and one-time use (rotation).
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    /** Saves a new row in the DB and returns the signed refresh JWT that points to it. */
    @Transactional
    public String create(User user) {
        String tokenId = UUID.randomUUID().toString();   // becomes the "jti" claim

        refreshTokenRepository.save(RefreshToken.builder()
                .tokenId(tokenId)
                .user(user)
                .expiresAt(Instant.now().plusMillis(jwtUtil.getRefreshExpirationMs()))
                .build());

        return jwtUtil.generateRefreshToken(user.getUsername(), tokenId);
    }

    /**
     * 1. JWT check: signature, expiry and "type": "refresh" (an access token is rejected)
     * 2. DB check: the jti exists and was not used/revoked
     * Marks the token as used and returns its owner. Throws InvalidRefreshTokenException otherwise.
     * noRollbackFor: when reuse is detected, the "revoke all" must be saved even though we throw.
     */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public User consume(String refreshJwt) {
        Claims claims = parseOrThrow(refreshJwt);

        RefreshToken token = refreshTokenRepository.findByTokenId(claims.getId())
                .orElseThrow(InvalidRefreshTokenException::new);

        if (token.isRevoked()) {
            // A token that was already used came back -> someone copied it. Log the user out everywhere.
            refreshTokenRepository.revokeAllByUser(token.getUser());
            throw new InvalidRefreshTokenException();
        }

        token.setRevoked(true);                          // rotation: this token will not work again
        return token.getUser();
    }

    /** Logout: the refresh token stops working. An invalid token is ignored - nothing to revoke. */
    @Transactional
    public void revoke(String refreshJwt) {
        try {
            Claims claims = jwtUtil.parseRefreshToken(refreshJwt);
            refreshTokenRepository.findByTokenId(claims.getId())
                    .ifPresent(token -> token.setRevoked(true));
        } catch (JwtException | IllegalArgumentException e) {
            // forged / expired / not a refresh token: there is nothing to log out
        }
    }

    private Claims parseOrThrow(String refreshJwt) {
        try {
            return jwtUtil.parseRefreshToken(refreshJwt);
        } catch (JwtException | IllegalArgumentException e) {
            // forged, expired, not a JWT, or an ACCESS token sent instead of a refresh token
            throw new InvalidRefreshTokenException();
        }
    }
}
