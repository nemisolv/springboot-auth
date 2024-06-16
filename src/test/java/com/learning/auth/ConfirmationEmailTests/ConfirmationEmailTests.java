package com.learning.auth.ConfirmationEmailTests;

import com.learning.auth.entity.ConfirmationEmail;
import com.learning.auth.entity.MailType;
import com.learning.auth.repository.ConfirmationEmailRepository;
import com.learning.auth.repository.UserRepository;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.annotation.Rollback;

import java.util.List;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
//@Rollback(false)
public class ConfirmationEmailTests {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ConfirmationEmailRepository confirmationEmailRepository;

    @Test
    public void testListConfirmationEmailsByUserIdAndMailType() {
        Long userId =11l;
       List<ConfirmationEmail> list= confirmationEmailRepository.findByTypeAndUserId(MailType.REGISTRATION_CONFIRMATION, userId)
                ;

        Assertions.assertThat(list).isNotEmpty();
        list.forEach(System.out::println);


    }
}
