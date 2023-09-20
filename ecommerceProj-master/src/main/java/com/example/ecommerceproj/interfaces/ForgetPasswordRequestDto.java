package com.example.ecommerceproj.interfaces;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ForgetPasswordRequestDto {
    private String email;

}
