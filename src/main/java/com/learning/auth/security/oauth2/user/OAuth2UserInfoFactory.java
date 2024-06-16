package com.learning.auth.security.oauth2.user;

import com.learning.auth.entity.AuthProvider;
import com.learning.auth.exception.OAuth2AuthenticationProcessionException;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOauth2UserInfo(String registrationId, Map<String,Object> attributes)  {
        if(registrationId.equalsIgnoreCase(AuthProvider.GOOGLE.getValue())) {
            return new GoogleOAuth2UserInfo(attributes);
        }else if(registrationId.equalsIgnoreCase(AuthProvider.FACEBOOK.getValue())) {
            return new FacebookOAuth2UserInfo(attributes);
        }else if(registrationId.equalsIgnoreCase(AuthProvider.GITHUB.getValue()))    {
            return new GithubOAuth2UserInfo(attributes);
        }else {
            throw new OAuth2AuthenticationProcessionException("Sorry! Login with " + registrationId + " is not supported yet!");
        }

    }
}