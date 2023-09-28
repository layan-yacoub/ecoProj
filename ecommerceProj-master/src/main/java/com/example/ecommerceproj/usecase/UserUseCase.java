package com.example.ecommerceproj.usecase;
import com.example.ecommerceproj.domain.User;
import com.example.ecommerceproj.interfaces.EmailService;
import com.example.ecommerceproj.interfaces.OTPValidationException;
import com.example.ecommerceproj.interfaces.UserDbo;
import com.example.ecommerceproj.interfaces.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

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

    public void sendOTPByEmail(String email) throws UserNotFoundException {
        Optional<UserDbo> userOptional = userRepoInterface.findByEmail(email);

        if (userOptional.isPresent()) {
            UserDbo user = userOptional.get();
            userRepoInterface.generateOTPToUser(user);
            emailService.sendEmail(user.getEmail(), "OTP Verification", "Your OTP: " + user.getOtp());
        } else {
            throw new UserNotFoundException("User not found for email: " + email);

        }
    }

    public void confirmOTP(String email, String otp) throws UserNotFoundException {
        Optional<UserDbo> userOptional = userRepoInterface.findByEmail(email);

        if (userOptional.isPresent()) {
            UserDbo userDbo = userOptional.get();

            if (otp.equals(userDbo.getOtp())) {
                emailService.sendConfirmationEmail(userDbo);
            } else {
                throw new OTPValidationException("OTP validation failed for email: " + email);
            }
        } else {
            throw new UserNotFoundException("User not found for email: " + email);

        }
    }


    public boolean loginConfirmation(String email, byte[] hashedPassword) {
        Optional<UserDbo> userOptional = userRepoInterface.findByEmail(email);

        if (userOptional.isPresent()) {
            UserDbo user = userOptional.get();
            // Validate the password
            return Arrays.equals(hashedPassword, user.getHashedPassword());
        } else {
            // Handle the case when the user is not found
            return false;
        }
    }


    public void changePassword(String email, byte[] newPassword) {
         UserDbo userDbo = userRepoInterface.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found for email: " + email));
        userRepoInterface.changePassword(userDbo, newPassword);
    }
}

