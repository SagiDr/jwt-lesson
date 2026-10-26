package com.example.jwtlesson.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * A refresh token, one row per login (table refresh_tokens).
 * Only the SHA-256 HASH of the token is stored - like passwords, a DB leak does not leak usable tokens.
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

    // SHA-256 of the token as hex (64 chars). The raw token is sent to the client once and never stored.
    @Column(nullable = false, unique = true, length = 64)
    @EqualsAndHashCode.Include   // natural key: the hash is unique
    private String tokenHash;

    // Many tokens per user (one per login / refresh)
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private Instant expiresAt;

    // true once the token was used (rotation) or after logout
    @Column(nullable = false)
    private boolean revoked;
}
