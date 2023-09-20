package com.example.ecommerceproj.interfaces;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ResponseLoginDto {
    private String email;
    private byte[] hashedPassword;
}
