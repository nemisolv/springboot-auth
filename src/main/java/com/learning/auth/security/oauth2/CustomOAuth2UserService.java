package com.learning.auth.security.oauth2;

import com.learning.auth.entity.AuthProvider;
import com.learning.auth.entity.User;
import com.learning.auth.exception.OAuth2AuthenticationProcessionException;
import com.learning.auth.helper.UserHelper;
import com.learning.auth.repository.UserRepository;
import com.learning.auth.security.oauth2.user.OAuth2UserInfo;
import com.learning.auth.security.oauth2.user.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepo;
    private final UserHelper userHelper;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        try {
            return processOAuth2User(userRequest, oAuth2User);

        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // trigger OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }

    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOauth2UserInfo(
                userRequest.getClientRegistration().getRegistrationId(),
                oAuth2User.getAttributes());
    //because gitHub does not provide email, we don't need to check for email
//        if (oAuth2UserInfo.getEmail().isEmpty()) {
//            throw new OAuth2AuthenticationProcessionException("Email not found from OAuth2 provider");
//        }
        Optional<User> userOptional = userRepo.findByEmail(oAuth2UserInfo.getEmail());
        User user;
        if(userOptional.isPresent()) {
            user = userOptional.get();
            if (!user.getAuthProvider().equals(AuthProvider.valueOf(userRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessionException("Looks like you're signed up with " +
                        user.getAuthProvider().getValue() + " account. Please use your " + user.getAuthProvider().getValue() +
                        " account to login.");
            }
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(userRequest, oAuth2UserInfo);
        }



        return user;
    }
    private User registerNewUser(OAuth2UserRequest userRequest, OAuth2UserInfo oauth2UserInfo) {
        User user = new User();
       setName(oauth2UserInfo.getName(),user);
        user.setEmail(oauth2UserInfo.getEmail());
        String username = userHelper.generateUsername(oauth2UserInfo.getName(),"");
        user.setUsername(username);
        user.setAuthProvider(AuthProvider.valueOf(userRequest.getClientRegistration().getRegistrationId()));
        user.setProviderId(oauth2UserInfo.getId());
        user.setPicture(oauth2UserInfo.getImageUrl());

        return userRepo.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oauth2UserInfo) {
        existingUser.setPicture(oauth2UserInfo.getImageUrl());
        return userRepo.save(existingUser);
    }

    private void setName(String name, User user) {
        String[] names = name.split(" ");
        user.setFirstName(names[0]);
        if(names.length>1) {
            user.setLastName(names[1]);
        }
    }
}
