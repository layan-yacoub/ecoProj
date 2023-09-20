package com.example.ecommerceproj.usecase;
import com.example.ecommerceproj.domain.User;
import com.example.ecommerceproj.interfaces.EmailService;
import com.example.ecommerceproj.interfaces.OTPValidationException;
import com.example.ecommerceproj.interfaces.UserDbo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@RequiredArgsConstructor
@Component
public class UserUseCase {
    private final UserRepoInterface userRepoInterface;
    private final EmailService emailService;

    public User register(User user) {

        return userRepoInterface.createUser(user);
    }

    public boolean existsByEmail(String email) {

        return userRepoInterface.existsByEmail(email);
    }

    public void sendOTPByEmail(String email) {
        UserDbo user = userRepoInterface.findByEmail(email);
        userRepoInterface.generateOTPToUser(user);
        emailService.sendEmail(user.getEmail(), "OTP Verification", "Your OTP: " + user.getOtp());
    }

    public void confirmOTP(String email, String otp) {
        UserDbo userDbo = userRepoInterface.findByEmail(email);

        if (otp.equals(userDbo.getOtp())) {
            emailService.sendConfirmationEmail(userDbo);
        } else {
            throw new OTPValidationException("OTP validation failed for email: " + email);
        }
    }

    public boolean loginConfirmation(String email, byte[] hashedPassword) {
        UserDbo user = userRepoInterface.findByEmail(email);
        // Validate the password
        return Arrays.equals(hashedPassword, user.getHashedPassword());
    }

    public void changePassword(String email, byte[] newPassword) {
        UserDbo userDbo = userRepoInterface.findByEmail(email);
        userRepoInterface.changePassword(userDbo, newPassword);
    }
}

