package com.learning.auth.payload;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class RegisterRequest {
    private String email;
    private String password;
    private String firstName;
    private String lastName;

}
