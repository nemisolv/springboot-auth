package com.learning.auth.repository;

import com.learning.auth.entity.ConfirmationEmail;
import com.learning.auth.entity.MailType;
import com.learning.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.Repository;

import java.util.List;
import java.util.Optional;

public interface ConfirmationEmailRepository extends CrudRepository<ConfirmationEmail, Long> {
    List<ConfirmationEmail> findByUserId(Long userId);

    Optional<ConfirmationEmail> findByUserAndToken(User user, String token);

    List<ConfirmationEmail> findByTypeAndUserId(MailType type, Long userId);
}
