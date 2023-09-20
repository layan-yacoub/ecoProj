package com.example.ecommerceproj.interfaces;

import com.example.ecommerceproj.domain.User;
import org.springframework.stereotype.Component;

@Component
public class UserToRegisterUserResponseDtoConverter {
    public RegisterUserResponseDto convert(User user) {
        return RegisterUserResponseDto
                .builder()
                .email(user.getEmail())
                .hashedPassword(user.getHashedPassword())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .address(user.getAddress())
                .build();
    }
}