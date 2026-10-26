package com.example.jwtlesson.repository;

import com.example.jwtlesson.entity.RefreshToken;
import com.example.jwtlesson.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    // Loads the token together with its user (one query) - the user is needed after the transaction ends
    @EntityGraph(attributePaths = "user")
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    // A used token came back (probably stolen): revoke every active refresh token of that user
    @Modifying
    @Query("UPDATE RefreshToken t SET t.revoked = true WHERE t.user = :user AND t.revoked = false")
    int revokeAllByUser(@Param("user") User user);
}
