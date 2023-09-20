package com.example.ecommerceproj.interfaces;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.DynamicUpdate;

import java.time.LocalDateTime;

@Table(name = "users")
    @Getter
    @Setter
    @NoArgsConstructor
    @Entity
    @DynamicUpdate
    @ToString
    @Builder
    public class UserDbo {
        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE)
        @Column(name = "id", nullable = false)
        private long id;
        @Column(name = "email")
        private String email;
        @Column(name = "hashed_password")
        private byte[] hashedPassword;
        @Column(name = "first_name")
        private String firstName;
        @Column(name = "last_name")
        private String lastName;
        @Column(name = "phone_number", unique = true)
        private String phoneNumber;
        @Column(name = "address")
        private String address ;
        @Column(name="otp")
        private String otp; // Field to store OTP
        @Column(name="otpExpiration")
        private LocalDateTime otpExpiration; // Field to store OTP expiration time

        public UserDbo( String email, byte[] hashedPassword) {
            this.email = email;
            this.hashedPassword = hashedPassword;
        }


    public UserDbo(long id, String email, byte[] hashedPassword, String firstName, String lastName, String phoneNumber, String address, String otp, LocalDateTime otpExpiration) {
        this.id = id;
        this.email = email;
        this.hashedPassword = hashedPassword;
        this.firstName = firstName;
        this.lastName = lastName;
        this.phoneNumber = phoneNumber;
        this.address = address;
        this.otp = null;
        this.otpExpiration = null;
    }

    public UserDbo(String email, byte[] hashedPassword, String firstName, String lastName, String phoneNumber, String address, String otp, LocalDateTime otpExpiration) {
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

