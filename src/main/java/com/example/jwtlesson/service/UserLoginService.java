package com.example.jwtlesson.service;

import com.example.jwtlesson.dto.LoginRequest;
import com.example.jwtlesson.dto.LoginResponse;
import com.example.jwtlesson.dto.RefreshRequest;
import com.example.jwtlesson.dto.RegisterRequest;
import com.example.jwtlesson.dto.UserResponse;
import com.example.jwtlesson.entity.Role;
import com.example.jwtlesson.entity.RoleName;
import com.example.jwtlesson.entity.User;
import com.example.jwtlesson.exception.InvalidRefreshTokenException;
import com.example.jwtlesson.exception.UsernameTakenException;
import com.example.jwtlesson.repository.RoleRepository;
import com.example.jwtlesson.repository.UserRepository;
import com.example.jwtlesson.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserLoginService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * 1. AuthenticationManager checks name + password (throws BadCredentialsException if wrong)
     * 2. JwtUtil creates a signed access token, RefreshTokenService a refresh token
     */
    public LoginResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userDetails.getUsername()));

        return issueTokens(userDetails, user);
    }

    /**
     * Exchanges a refresh token for a NEW access token + a NEW refresh token (rotation).
     * No password needed - the refresh token is the proof. The old refresh token stops working.
     */
    public LoginResponse refresh(RefreshRequest request) {
        User user = refreshTokenService.consume(request.refreshToken());

        // Load the CURRENT user (like JwtAuthFilter): a disabled user cannot refresh,
        // and role changes are in the new access token
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        if (!userDetails.isEnabled()) {
            throw new InvalidRefreshTokenException();
        }

        return issueTokens(userDetails, user);
    }

    /**
     * Logout: the refresh token is revoked.
     * The access token keeps working until it expires - that is why it lives only 15 minutes.
     */
    public void logout(RefreshRequest request) {
        refreshTokenService.revoke(request.refreshToken());
    }

    /** New users always get ROLE_USER only. Admins are never created through this endpoint. */
    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new UsernameTakenException(request.username());
        }

        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new IllegalStateException("ROLE_USER missing - did DataInitializer run?"));

        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .roles(new HashSet<>(Set.of(userRole)))
                .build();

        return UserResponse.from(userRepository.save(user));
    }

    private LoginResponse issueTokens(UserDetails userDetails, User user) {
        String accessToken = jwtUtil.generateToken(userDetails);
        String refreshToken = refreshTokenService.create(user);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return new LoginResponse(accessToken, "Bearer", jwtUtil.getExpirationMs(),
                refreshToken, jwtUtil.getRefreshExpirationMs(),
                userDetails.getUsername(), roles);
    }
}
