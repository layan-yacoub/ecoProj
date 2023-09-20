package com.example.ecommerceproj.interfaces;


import com.example.ecommerceproj.domain.User;
import org.springframework.stereotype.Component;

@Component

public class UserDboToUserConverter {
    public User convert(UserDbo userDbo) {
        return User.builder().build();
    }
}