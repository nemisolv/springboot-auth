package com.learning.auth.controller;

import com.learning.auth.entity.User;
import com.learning.auth.payload.ChangePasswordRequest;
import com.learning.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/users")
public class UserController {
    private final UserService userService;

    @PatchMapping("/change")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest passwordRequest, @AuthenticationPrincipal User user) {
        userService.changePassword(passwordRequest, user);
        return ResponseEntity.accepted().build();
    }
}
