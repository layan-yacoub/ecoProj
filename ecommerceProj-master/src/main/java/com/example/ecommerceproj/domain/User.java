package com.example.ecommerceproj.domain;

import jakarta.persistence.Column;
import lombok.*;

import java.time.LocalDateTime;

//business logic
@Getter
@Setter
@EqualsAndHashCode
@RequiredArgsConstructor
public class User {

    private long id;
    private String email;
    private byte[] hashedPassword;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String address;
    private String otp;
    private LocalDateTime otpExpiration;
    @Builder
    public User(String email, byte[] hashedPassword, String firstName, String lastName, String phoneNumber, String address, String otp, LocalDateTime otpExpiration) {
        this.email = email;
        this.hashedPassword = hashedPassword;
        this.firstName = firstName;
        this.lastName = lastName;
        this.phoneNumber = phoneNumber;
        this.address = address;
        this.otp = null;
        this.otpExpiration = null;
    }
}