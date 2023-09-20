package com.example.ecommerceproj.interfaces;

import com.example.ecommerceproj.domain.User;

public class RegisterUserDtoToUserConverter {

    // Convert the responseDto to a User object
    public static User convertToUser(RegisterUserResponseDto responseDto) {
        User user = new User();
        user.setEmail(responseDto.getEmail());
        user.setFirstName(responseDto.getFirstName());
        user.setLastName(responseDto.getLastName());
        user.setAddress(responseDto.getAddress());
        user.setPhoneNumber(responseDto.getPhoneNumber());
        user.setHashedPassword(responseDto.getHashedPassword());
        user.setOtp(null);
        user.setOtpExpiration(null);
        return user;


}}
