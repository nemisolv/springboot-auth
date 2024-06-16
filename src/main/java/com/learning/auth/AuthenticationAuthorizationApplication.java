package com.learning.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;

@SpringBootApplication
@EnableJpaAuditing
public class AuthenticationAuthorizationApplication {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        SpringApplication.run(AuthenticationAuthorizationApplication.class, args);
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
//        keyPairGenerator.initialize(256);
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
//        System.out.println("Private Key: " + privateKey.getS());
    }

}
