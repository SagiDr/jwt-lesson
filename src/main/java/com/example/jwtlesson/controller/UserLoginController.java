package com.example.jwtlesson.controller;

import com.example.jwtlesson.dto.LoginRequest;
import com.example.jwtlesson.dto.LoginResponse;
import com.example.jwtlesson.dto.RefreshRequest;
import com.example.jwtlesson.dto.RegisterRequest;
import com.example.jwtlesson.dto.UserResponse;
import com.example.jwtlesson.service.UserLoginService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

/**
 * Public endpoints (permitAll in SecurityConfig): login, register, refresh, logout.
 * The controller only receives HTTP and delegates - the logic lives in UserLoginService.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserLoginController {

    private final UserLoginService userLoginService;

    // POST /api/auth/login   {"username":"admin","password":"Admin123!"}
    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return userLoginService.login(request);
    }

    // POST /api/auth/register   {"username":"dana","password":"Dana1234!"}
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@Valid @RequestBody RegisterRequest request) {
        return userLoginService.register(request);
    }

    // POST /api/auth/refresh   {"refreshToken":"..."}  -> new access token + new refresh token
    // Public on purpose: it is called exactly when the access token has expired
    @PostMapping("/refresh")
    public LoginResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return userLoginService.refresh(request);
    }

    // POST /api/auth/logout   {"refreshToken":"..."}  -> 204, the refresh token stops working
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody RefreshRequest request) {
        userLoginService.logout(request);
    }
}
