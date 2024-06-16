package com.learning.auth.entity;


import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "confirmation_emails")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class ConfirmationEmail {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    private String token;

    @Enumerated(EnumType.STRING)
    private MailType type;

    private boolean revoked;



    @Column(name = "confirmed_at")
    private LocalDateTime confirmedAt;
    @Column(name = "expired_at")

    private LocalDateTime expiredAt;

    @Override
    public String toString() {
        return "ConfirmationEmail{" +
                "id=" + id +
                ", user=" + user +
                ", token='" + token + '\'' +
                ", type=" + type +
                ", revoked=" + revoked +
                ", confirmedAt=" + confirmedAt +
                ", expiredAt=" + expiredAt +
                '}';
    }

}
