package com.learning.auth.util;

import com.learning.auth.helper.EmailSettingBag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;
import java.util.concurrent.ThreadLocalRandom;

@Slf4j
public final class Utility {

    public static JavaMailSenderImpl prepareMailSender(EmailSettingBag settingBag) {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(settingBag.getHost());
        String port = settingBag.getPort();
        try {
            mailSender.setPort(Integer.parseInt(port));
        }catch(NumberFormatException e){
            log.error("Invalid port number: {}", port);
            throw e;
        }
        mailSender.setUsername(settingBag.getUsername());
        mailSender.setPassword(settingBag.getPassword());
        // set properties for mail sender
        Properties properties = new Properties();
        properties.setProperty("mail.smtp.auth", settingBag.getSmtpAuth());
        properties.setProperty("mail.smtp.starttls.enable", settingBag.getSmtpSecured());
        mailSender.setJavaMailProperties(properties);
        return mailSender;
    }

    public String genRandomCode() {
        return genRandomCode(6);
    }

    public String genRandomCode(int length) {
        int random = ThreadLocalRandom.current().nextInt((int) Math.pow(10, length - 1), (int) Math.pow(10, length));
        return String.valueOf(random);
    }


}
