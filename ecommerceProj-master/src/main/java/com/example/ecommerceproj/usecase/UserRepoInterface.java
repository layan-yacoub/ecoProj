package com.example.ecommerceproj.usecase;

import com.example.ecommerceproj.domain.User;
import com.example.ecommerceproj.interfaces.UserDbo;

import java.util.Optional;

public interface UserRepoInterface {
    User createUser(User user);
    boolean existsByEmail(String email);

    Optional<UserDbo> findByEmail(String email);

    UserDbo findUserDboById(Long userId);

    void generateOTPToUser(UserDbo user);

    void changePassword(UserDbo userDbo, byte[] newPassword);
}