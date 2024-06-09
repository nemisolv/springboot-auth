package com.learning.auth.controller;

import com.learning.auth.payload.AuthenticationRequest;
import com.learning.auth.payload.AuthenticationResponse;
import com.learning.auth.payload.RegisterRequest;
import com.learning.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest authRequest) {
        AuthenticationResponse response = authService.authenticate(authRequest);
        return ResponseEntity.ok(response);

    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest authRequest) throws BadRequestException {
        AuthenticationResponse response = authService.register(authRequest);
        return ResponseEntity.ok(response);
    }



    @GetMapping("/greeting")
    public String hello() {
        return "hello";
    }




    @PostMapping("/refresh_token")
    public void refreshToken(HttpServletRequest req, HttpServletResponse res) throws IOException {
        authService.refreshToken(req, res);
    }
}
