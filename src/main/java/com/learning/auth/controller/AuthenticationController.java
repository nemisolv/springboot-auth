package com.learning.auth.controller;

import com.learning.auth.payload.AuthenticationRequest;
import com.learning.auth.payload.AuthenticationResponse;
import com.learning.auth.payload.RegisterRequest;
import com.learning.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    public String greeting() {
        return "Hello World";
    }

//    @PostMapping("/refresh_token")
//    public
}
