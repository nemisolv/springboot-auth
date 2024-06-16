package com.learning.auth.service;

import com.learning.auth.payload.auth.AuthenticationRequest;
import com.learning.auth.payload.auth.AuthenticationResponse;
import com.learning.auth.payload.auth.RegisterRequest;
import com.learning.auth.payload.auth.VerificationMfaRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.coyote.BadRequestException;

import java.io.IOException;

public interface AuthService {
    AuthenticationResponse authenticate(AuthenticationRequest authRequest);
    void register(RegisterRequest authRequest) throws BadRequestException, com.learning.auth.exception.BadRequestException;
    void refreshToken(HttpServletRequest req, HttpServletResponse res) throws IOException;

    AuthenticationResponse verifyMfaCode(VerificationMfaRequest verificationMfaRequest);
    void verifyEmail(String token) throws com.learning.auth.exception.BadRequestException;

}

