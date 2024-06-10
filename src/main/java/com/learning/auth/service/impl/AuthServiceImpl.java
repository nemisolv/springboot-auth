package com.learning.auth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learning.auth.entity.*;
import com.learning.auth.helper.UserHelper;
import com.learning.auth.payload.auth.AuthenticationRequest;
import com.learning.auth.payload.auth.AuthenticationResponse;
import com.learning.auth.payload.auth.RegisterRequest;
import com.learning.auth.payload.auth.VerificationMfaRequest;
import com.learning.auth.payload.user.FullInfoUser;
import com.learning.auth.repository.RoleRepository;
import com.learning.auth.repository.TokenRepository;
import com.learning.auth.repository.UserRepository;
import com.learning.auth.service.AuthService;
import com.learning.auth.service.JwtService;
import com.learning.auth.service.TwoFactorAuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final TokenRepository tokenRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;
    private final UserHelper userHelper;
    private final TwoFactorAuthenticationService tfaService;

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword())
            );

            User user = (User) authentication.getPrincipal();

            if (!user.isVerified()) {
                throw new BadCredentialsException("User not verified");
            }
            // check if user enable mfa
            if(user.isMfaEnabled()) {
                return AuthenticationResponse.builder()
                        .accessToken("")
                        .refreshToken("")
                        .secretImageUri(tfaService.generateQrCodeImageUri(user.getSecret()))
                        .mfaEnabled(true)
                        .build();

            }



            return getAuthenticationResponse(user);


        }catch (LockedException ex) {
            throw new LockedException("User account is locked");
        }
        catch (AuthenticationException ex) {
            throw new BadCredentialsException(ex.getMessage());
        }

    }

    @Override
    @Transactional
    public AuthenticationResponse register(RegisterRequest authRequest) throws BadRequestException {
        Optional<User> user = userRepo.findByEmail(authRequest.getEmail());
        if (user.isPresent()) {
            throw new BadRequestException("User already exists");
        }
        Role role = roleRepo.findByName(RoleName.USER).get();



        String username = userHelper.generateUsername(authRequest.getFirstName(), authRequest.getLastName());
        User newUser = User.builder()
                .email(authRequest.getEmail())
                .username(username)
                .password(passwordEncoder.encode(authRequest.getPassword()))
                .firstName(authRequest.getFirstName())
                .lastName(authRequest.getLastName())
                .verified(false).roles(new HashSet<>(Arrays.asList(role)))
                .build();

        User savedUser = userRepo.save(newUser);


        return getAuthenticationResponse(savedUser);
    }

    @Override
    public void refreshToken(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        String userEmail = jwtService.extractUsername(refreshToken);
        if(userEmail!=null) {
                var userDetails = userRepo.findByEmail(userEmail)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
                if(jwtService.isValidToken(refreshToken,userDetails)) {
                    var newToken = jwtService.generateToken(userDetails);
                    revokeAllUserTokens(userDetails);

                    saveUserToken(userDetails, newToken);

                    var authResponse = AuthenticationResponse.builder()
                            .accessToken(newToken)
                            .refreshToken(refreshToken).build();
                    new ObjectMapper().writeValue(res.getOutputStream(), authResponse);
                }
        }
    }

    @Override
    public AuthenticationResponse verifyMfaCode(VerificationMfaRequest verificationMfaRequest) {
        User user = userRepo.findByEmail(verificationMfaRequest.getEmail()).orElseThrow();
        if(!tfaService.isOtpValid(user.getSecret(), verificationMfaRequest.getCode())) {
            throw new BadCredentialsException("Code is not correct");
        }



        return getAuthenticationResponse(user);
    }

    private AuthenticationResponse getAuthenticationResponse(User user) {

        // instead of adding user's info to token, let's separate it
        FullInfoUser userInfo = modelMapper.map(user, FullInfoUser.class);

        String token = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);

        saveUserToken(user, token);
        return AuthenticationResponse.builder()
                .userData(userInfo)
                .accessToken(token).refreshToken(refreshToken).build();
    }

    private void saveUserToken(User user, String token) {
        var tokenStore = Token.builder()
                .token(token)
                .user(user)
                .type(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepo.save(tokenStore);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepo.findAllValidTokenByUser(user.getId());
        if(validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(token -> {
            token.setRevoked(true);
            token.setExpired(true);
            tokenRepo.save(token);
        });
    }
}
