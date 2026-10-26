package com.example.jwtlesson.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

/**
 * Creates and verifies JWT tokens (HMAC-SHA256 signature with a server-side secret).
 * Two kinds, told apart by the "type" claim:
 *   access  - 15 minutes, sent on every request ("Authorization: Bearer ...")
 *   refresh - 7 days, accepted ONLY by POST /api/auth/refresh
 */
@Component
public class JwtUtil {

    private static final String TYPE_CLAIM = "type";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    private final SecretKey key;
    private final long expirationMs;
    private final long refreshExpirationMs;

    public JwtUtil(@Value("${jwt.secret}") String base64Secret,
                   @Value("${jwt.expiration-ms}") long expirationMs,
                   @Value("${jwt.refresh-expiration-ms}") long refreshExpirationMs) {
        // Throws WeakKeyException if the secret is shorter than 256 bits
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
        this.expirationMs = expirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    /** Access token - called after a successful login or refresh. */
    public String generateToken(UserDetails userDetails) {
        Date now = new Date();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Jwts.builder()
                .subject(userDetails.getUsername())                 // "sub"
                .claim(TYPE_CLAIM, TYPE_ACCESS)                     // "type": "access"
                .claim("roles", roles)                              // custom claim, for the client to read
                .issuedAt(now)                                      // "iat"
                .expiration(new Date(now.getTime() + expirationMs)) // "exp"
                .signWith(key)                                      // HS256 for a 256-bit key
                .compact();                                         // header.payload.signature
    }

    /**
     * Refresh token - a JWT too, but with "type": "refresh" and a unique id ("jti").
     * No roles inside: it is not used to access anything, only to get a new access token.
     * The jti is saved in the DB, so the token can be used once and revoked on logout.
     */
    public String generateRefreshToken(String username, String tokenId) {
        Date now = new Date();
        return Jwts.builder()
                .subject(username)                                         // "sub"
                .id(tokenId)                                               // "jti" - the row in refresh_tokens
                .claim(TYPE_CLAIM, TYPE_REFRESH)                           // "type": "refresh"
                .issuedAt(now)                                             // "iat"
                .expiration(new Date(now.getTime() + refreshExpirationMs)) // "exp" - 7 days
                .signWith(key)
                .compact();
    }

    /**
     * Verifies the signature and the expiry, then returns the payload.
     * Throws JwtException (SignatureException, ExpiredJwtException, MalformedJwtException ...)
     * if the token was changed, expired or is not a JWT.
     */
    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Used by JwtAuthFilter: only an ACCESS token is accepted - a refresh token is rejected. */
    public String extractUsername(String token) {
        return parseTyped(token, TYPE_ACCESS).getSubject();
    }

    /** Used by POST /api/auth/refresh: only a REFRESH token is accepted - an access token is rejected. */
    public Claims parseRefreshToken(String token) {
        return parseTyped(token, TYPE_REFRESH);
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public long getRefreshExpirationMs() {
        return refreshExpirationMs;
    }

    private Claims parseTyped(String token, String expectedType) {
        Claims claims = parseClaims(token);
        if (!expectedType.equals(claims.get(TYPE_CLAIM, String.class))) {
            throw new JwtException("Expected a " + expectedType + " token");
        }
        return claims;
    }
}
