package com.learning.auth.service;

import com.learning.auth.payload.AuthenticationRequest;
import com.learning.auth.payload.AuthenticationResponse;
import com.learning.auth.payload.RegisterRequest;
import org.apache.coyote.BadRequestException;

public interface AuthService {
    AuthenticationResponse authenticate(AuthenticationRequest authRequest);
    AuthenticationResponse register(RegisterRequest authRequest) throws BadRequestException;

}

