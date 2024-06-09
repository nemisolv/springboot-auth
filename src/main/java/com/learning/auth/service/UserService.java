package com.learning.auth.service;

import com.learning.auth.entity.User;
import com.learning.auth.payload.ChangePasswordRequest;

public interface UserService {
    void changePassword(ChangePasswordRequest passwordRequest, User ser);
}
