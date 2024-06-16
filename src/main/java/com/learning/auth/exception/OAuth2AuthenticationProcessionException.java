package com.learning.auth.exception;

import org.springframework.security.core.AuthenticationException;

public class OAuth2AuthenticationProcessionException extends AuthenticationException {
public OAuth2AuthenticationProcessionException(String msg) {
    super(msg);
}

public OAuth2AuthenticationProcessionException(String msg,Throwable t) {super(msg,t);}




}