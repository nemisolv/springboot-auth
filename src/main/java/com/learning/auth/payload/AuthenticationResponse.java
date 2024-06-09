package com.learning.auth.payload;

import com.learning.auth.payload.user.FullInfoUser;
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    private String accessToken;
    private String refreshToken;
    private FullInfoUser userData;
}
