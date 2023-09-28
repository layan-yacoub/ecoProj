package com.example.ecommerceproj.auth;

import com.example.ecommerceproj.interfaces.Role;
import com.example.ecommerceproj.token.Token;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    private String firstName;
    private String lastName;
    private String email;
    private byte[] password;
    private String Address;
    private String PhoneNumber;
    private Role role;
    private String otp;
    private LocalDateTime otpExpiration;}