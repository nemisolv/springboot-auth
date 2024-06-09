package com.learning.auth.service;

import com.learning.auth.payload.AuthenticationRequest;
import com.learning.auth.payload.AuthenticationResponse;
import com.learning.auth.payload.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.coyote.BadRequestException;

import java.io.IOException;

public interface AuthService {
    AuthenticationResponse authenticate(AuthenticationRequest authRequest);
    AuthenticationResponse register(RegisterRequest authRequest) throws BadRequestException;
    void refreshToken(HttpServletRequest req, HttpServletResponse res) throws IOException;

}

