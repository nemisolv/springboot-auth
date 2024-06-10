package com.learning.auth.service;

public interface TwoFactorAuthenticationService {
    String generateNewSecret();

    String generateQrCodeImageUri(String secret);
    boolean isOtpValid(String secret, String code);

}
