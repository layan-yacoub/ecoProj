package com.example.ecommerceproj.interfaces;
import ch.qos.logback.classic.spi.LoggingEventVO;
import com.example.ecommerceproj.token.Token;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.DynamicUpdate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@Table(name = "users")
    @Getter
    @Setter
    @NoArgsConstructor
    @Entity
    @DynamicUpdate
    @AllArgsConstructor
    @ToString
    @Builder
    public class UserDbo implements UserDetails {
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

        @Enumerated(EnumType.STRING)
        private Role role ;

         @OneToMany(mappedBy = "users")
         private List<Token> tokens;

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


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return Arrays.toString(hashedPassword);
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

