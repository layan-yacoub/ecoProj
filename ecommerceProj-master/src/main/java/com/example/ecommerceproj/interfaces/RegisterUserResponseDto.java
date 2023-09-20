package com.example.ecommerceproj.interfaces;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public
class RegisterUserResponseDto {

    private String email;
    private byte[] hashedPassword;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String address;
    private String otp;
    private LocalDateTime otpExpiration;
}
