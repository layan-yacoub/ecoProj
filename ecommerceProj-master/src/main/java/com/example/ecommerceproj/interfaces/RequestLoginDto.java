package com.example.ecommerceproj.interfaces;

import lombok.Data;

@Data
public class RequestLoginDto {
    private String email;
    private byte[] hashedPassword;
}
