package com.learning.auth.payload.user;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter

public class FullInfoUser {
    private Long id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private boolean verified;
    private String picture;
    private boolean mfaEnabled;
}
