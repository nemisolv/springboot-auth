package com.learning.auth.repository;

import com.learning.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    User findByUsername(String username);


//    @Query("UPDATE User u SET u.mfaEnabled = ?2 WHERE u.id = ?1")
//    @Modifying
//    void enableMFA(Long userId, boolean enabled);
}
