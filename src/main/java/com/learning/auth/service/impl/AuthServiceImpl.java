package com.learning.auth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learning.auth.entity.*;
import com.learning.auth.exception.BadRequestException;
import com.learning.auth.helper.MailHelper;
import com.learning.auth.helper.UserHelper;
import com.learning.auth.payload.auth.AuthenticationRequest;
import com.learning.auth.payload.auth.AuthenticationResponse;
import com.learning.auth.payload.auth.RegisterRequest;
import com.learning.auth.payload.auth.VerificationMfaRequest;
import com.learning.auth.payload.user.FullInfoUser;
import com.learning.auth.repository.ConfirmationEmailRepository;
import com.learning.auth.repository.RoleRepository;
import com.learning.auth.repository.TokenRepository;
import com.learning.auth.repository.UserRepository;
import com.learning.auth.service.AuthService;
import com.learning.auth.service.JwtService;
import com.learning.auth.service.TwoFactorAuthenticationService;
import com.learning.auth.util.Constants;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
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
    private final MailHelper mailHelper;
    private final ConfirmationEmailRepository confirmationEmailRepo;

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
    public void register(RegisterRequest authRequest) throws BadRequestException {
        Optional<User> user = userRepo.findByEmail(authRequest.getEmail());
        Role role = roleRepo.findByName(RoleName.USER).get();
        if (user.isPresent() ) {
            if(user.get().isVerified()) {
                throw new BadRequestException("User already exists");

            }else {
                // update user info
                var userToUpdate = user.get();
                userToUpdate.setFirstName(authRequest.getFirstName());
                userToUpdate.setLastName(authRequest.getLastName());
                userToUpdate.setPassword(passwordEncoder.encode(authRequest.getPassword()));
                userRepo.save(userToUpdate);
                // revoke all old tokens before sending new verification email

                confirmationEmailRepo.findByTypeAndUserId(MailType.REGISTRATION_CONFIRMATION, userToUpdate.getId())
                        .forEach(confirmationEmail -> {
                            confirmationEmail.setRevoked(true);
                            confirmationEmailRepo.save(confirmationEmail);
                        });
                // send a new verification email

                sendVerificationEmail(userToUpdate);
            }
        }else {
            // create new user
            String username = userHelper.generateUsername(authRequest.getFirstName(), authRequest.getLastName());
            User newUser = User.builder()
                    .email(authRequest.getEmail())
                    .username(username)
                    .password(passwordEncoder.encode(authRequest.getPassword()))
                    .firstName(authRequest.getFirstName())
                    .lastName(authRequest.getLastName())
                    .verified(false).roles(new HashSet<>(Arrays.asList(role)))
                    .mfaEnabled(false)
                    .enabled(true)
                    .authProvider(AuthProvider.LOCAL) // default auth provider
                    .build();

            User savedUser = userRepo.save(newUser);

            // send verification email
            sendVerificationEmail(savedUser);
        }



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

    @Override
    public void verifyEmail(String token) throws BadRequestException {
        String email = jwtService.extractUsername(token);
        User user = userRepo.findByEmail(email).orElseThrow(() -> new BadRequestException("Invalid token"));
        Optional<ConfirmationEmail> tokenOptional = confirmationEmailRepo.findByUserAndToken(user, token);
        if(tokenOptional.isEmpty()) {
            throw new BadRequestException("Invalid token");
        }
        ConfirmationEmail confirmationEmail = tokenOptional.get();
        if(confirmationEmail.isRevoked() ) {
            throw new BadRequestException("Invalid token");
        }
        if(confirmationEmail.getExpiredAt().isBefore(LocalDateTime.now())) {
            throw new BadRequestException("Token expired");
        }
        // check if email already verified after checking token expired
        if(confirmationEmail.getConfirmedAt() != null) {
            throw new BadRequestException("Email already verified");
        }

        confirmationEmail.setConfirmedAt(LocalDateTime.now());
        user.setVerified(true);
        userRepo.save(user);
        confirmationEmailRepo.save(confirmationEmail);
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

    private void sendVerificationEmail(User user) {
        long expTime = Constants.EXP_TIME_REGISTRATION_EMAIL.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
        String token = jwtService.generateTokenWithExpire(user, expTime);
        var confirmationEmail = ConfirmationEmail.builder()
                .user(user)
                .token(token)
                .type(MailType.REGISTRATION_CONFIRMATION)
                .expiredAt(Constants.EXP_TIME_REGISTRATION_EMAIL)
                .revoked(false)
                .build();

        confirmationEmailRepo.save(confirmationEmail);

        String subject = String.format("Hi %s, please verify your email", user.getFirstName());
        String body = String.format(
                "<html>" +
                        "<head>" +
                        "    <style>" +
                        "        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f6f6f6; }" +
                        "        .email-container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }" +
                        "        .email-header { background-color: #4CAF50; color: #ffffff; padding: 10px; border-radius: 8px 8px 0 0; }" +
                        "        .email-content { padding: 20px; }" +
                        "        .email-footer { text-align: center; font-size: 12px; color: #777777; padding: 10px; }" +
                        "        .verify-button { display: inline-block; background-color: #4CAF50; color: #ffffff; padding: 10px 20px; border-radius: 4px; text-decoration: none; }" +
                        "    </style>" +
                        "</head>" +
                        "<body>" +
                        "    <div class='email-container'>" +
                        "        <div class='email-header'>" +
                        "            <h1>Verify Your Email</h1>" +
                        "        </div>" +
                        "        <div class='email-content'>" +
                        "            <p>Dear %s,</p>" +
                        "            <p>Please click the button below to verify your email address:</p>" +
                        "            <p><a class='verify-button' href='http://localhost:8080/api/v1/auth/verify-email?token=%s'>Verify Email</a></p>" +
                        "        </div>" +
                        "        <div class='email-footer'>" +
                        "            <p>If you did not request this, please ignore this email.</p>" +
                        "        </div>" +
                        "    </div>" +
                        "</body>" +
                        "</html>",
                user.getFirstName(), token
        );
        mailHelper.sendMail(user.getEmail(), subject, body);

    }
}
