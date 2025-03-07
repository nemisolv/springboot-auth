package com.learning.auth.service.impl;

import com.learning.auth.entity.User;
import com.learning.auth.payload.ChangePasswordRequest;
import com.learning.auth.repository.UserRepository;
import com.learning.auth.service.TwoFactorAuthenticationService;
import com.learning.auth.service.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepo;
    private final TwoFactorAuthenticationService tfaService;
    @Override
    public void changePassword(ChangePasswordRequest passwordRequest, User user) {
         if(!passwordEncoder.matches(passwordRequest.getOldPassword(),user.getPassword())) {
             throw new IllegalStateException("Wrong password");
         }

         if(!passwordRequest.getNewPassword().equals(passwordRequest.getConfirmationPassword())) {
             throw new IllegalStateException("Passwords are not the same");
         }

         user.setPassword(passwordEncoder.encode(passwordRequest.getNewPassword()));
         userRepo.save(user);
    }

    @Override
//    @Transactional
    public void enableMFA(boolean enabled, User user) {
        if(user.getSecret()!=null) {
            user.setSecret(tfaService.generateNewSecret());
        }
        user.setMfaEnabled(enabled);
        userRepo.save(user);
//        userRepo.enableMFA(user.getId(),enabled);

    }
}
