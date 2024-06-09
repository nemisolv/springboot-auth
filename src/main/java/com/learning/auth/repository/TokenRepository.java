package com.learning.auth.repository;

import com.learning.auth.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TokenRepository extends JpaRepository<Token, UUID> {

    @Query("""
            SELECT t FROM Token t inner join User u on t.user.id = u.id where
                        u.id = :userId and (t.expired = false or t.revoked = false)
            """)
    List<Token> findAllValidTokenByUser(Long userId);


    Optional<Token> findByToken(String token);

}
