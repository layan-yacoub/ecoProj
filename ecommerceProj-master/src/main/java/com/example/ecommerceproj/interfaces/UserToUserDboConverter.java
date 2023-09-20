package com.example.ecommerceproj.interfaces;


import com.example.ecommerceproj.domain.User;
import org.springframework.stereotype.Component;

@Component
public class UserToUserDboConverter {
    public UserDbo convert(User user) {
        return UserDbo.builder().build();
    }
}
