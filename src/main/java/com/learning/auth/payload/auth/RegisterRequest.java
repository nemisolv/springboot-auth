package com.learning.auth.payload.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

@Getter
@Setter
@Builder
public class RegisterRequest {
    @NotBlank(message = "Email can not be empty")
    private String email;
    @Length(min = 6, message = "Password must be at least 6 characters")
    private String password;
    private String firstName;
    private String lastName;

}
