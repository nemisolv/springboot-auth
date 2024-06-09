package com.learning.auth.helper;

import com.learning.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserHelper {
    private  final UserRepository userRepo;



    public  String generateUsername(String firstName, String lastName) {
        String username = firstName.toLowerCase() + lastName.toLowerCase();
//        do {
//            username = username + (int)(Math.random() * 1000);
//        }while(userRepo.findByUsername(username) != null);

        while(userRepo.findByUsername(username) != null) {
            username = username + (int)(Math.random() * 1000);
        }

        return username;
    }
}
