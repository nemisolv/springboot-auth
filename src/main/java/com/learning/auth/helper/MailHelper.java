package com.learning.auth.helper;

import com.learning.auth.service.SettingService;
import com.learning.auth.util.Utility;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMailMessage;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;

@Component
@Slf4j
@RequiredArgsConstructor
public class MailHelper {
    private final SettingService settingService;

    public void sendMail(String toAddress,String subject, String body)  {
        EmailSettingBag settingBag = settingService.getEmailSettings();
        JavaMailSenderImpl mailSender = Utility.prepareMailSender(settingBag);
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        try {
            helper.setFrom(settingBag.getMailFrom(), settingBag.getSenderName());
            helper.setTo(toAddress);
            helper.setSubject(subject);
            helper.setText(body, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            log.error("Error sending mail: -->", e);
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            log.error("Unsupported encoding: -->", e);
            throw new RuntimeException(e);
        }


    }
}
