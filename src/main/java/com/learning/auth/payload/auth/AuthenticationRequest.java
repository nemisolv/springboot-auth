package com.learning.auth.payload.auth;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

@Getter
@Setter
@Builder
public class AuthenticationRequest {
    @NotBlank(message = "Email can not be empty")
    private String email;
    @Length(min = 6, message = "Password must be at least 6 characters")

    private String password;
}
