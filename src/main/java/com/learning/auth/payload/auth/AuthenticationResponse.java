package com.learning.auth.payload.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.learning.auth.payload.user.FullInfoUser;
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class AuthenticationResponse {
    private String accessToken;
    private String refreshToken;
    private FullInfoUser userData;
    private String secretImageUri;
    private boolean mfaEnabled;
}
