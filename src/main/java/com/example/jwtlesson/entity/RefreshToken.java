package com.example.jwtlesson.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * One row per issued refresh token (table refresh_tokens).
 * The refresh token itself is a JWT; here we keep only its id ("jti") -
 * that is what makes it possible to use it only once and to revoke it on logout.
 */
@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true) // NOT @Data - see the lesson
@ToString(onlyExplicitlyIncluded = true)
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @ToString.Include
    private Long id;

    // The "jti" claim of the refresh JWT (a random UUID)
    @Column(nullable = false, unique = true, length = 36)
    @EqualsAndHashCode.Include   // natural key: the jti is unique
    @ToString.Include
    private String tokenId;

    // Many tokens per user (one per login / refresh)
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Same as the JWT "exp" - lets you see (and delete) old rows in the DB
    @Column(nullable = false)
    private Instant expiresAt;

    // true once the token was used (rotation) or after logout
    @Column(nullable = false)
    private boolean revoked;
}
