package com.example.ecommerceproj.domain;

import com.example.ecommerceproj.interfaces.Role;
import com.example.ecommerceproj.token.Token;
import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.OneToMany;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

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
    private Role role ;

    @OneToMany(mappedBy = "users")
    private List<Token> tokens;
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
    @Builder
    public User(long id, String email, byte[] hashedPassword, String firstName, String lastName, String phoneNumber, String address, String otp, LocalDateTime otpExpiration, Role role, List<Token> tokens) {
        this.id = id;
        this.email = email;
        this.hashedPassword = hashedPassword;
        this.firstName = firstName;
        this.lastName = lastName;
        this.phoneNumber = phoneNumber;
        this.address = address;
        this.otp = null;
        this.otpExpiration = null;
        this.role = role;
        this.tokens = tokens;
    }
}