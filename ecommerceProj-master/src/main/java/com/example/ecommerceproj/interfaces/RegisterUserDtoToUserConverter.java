package com.example.ecommerceproj.interfaces;

import com.example.ecommerceproj.auth.RegisterRequest;
import com.example.ecommerceproj.domain.User;

public class RegisterUserDtoToUserConverter {

    // Convert the responseDto to a User object
    public static User convertToUser(RegisterRequest registerRequest) {
        User user = new User();
        user.setEmail(registerRequest.getEmail());
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setHashedPassword(registerRequest.getPassword());
        user.setAddress(registerRequest.getAddress());
        user.setPhoneNumber(registerRequest.getPhoneNumber());
        user.setRole(registerRequest.getRole());
        user.setOtp(registerRequest.getOtp());
        user.setOtpExpiration(registerRequest.getOtpExpiration());
        return user;


}}
