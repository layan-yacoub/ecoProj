package com.example.ecommerceproj.interfaces;

import com.example.ecommerceproj.domain.User;
import com.example.ecommerceproj.usecase.UserRepoInterface;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.Random;

@RequiredArgsConstructor
@Repository
public class UserRepoSqlRepo implements UserRepoInterface  {

    private final UserJpaRepo userJpaRepo;
    private final UserDboToUserConverter userDboToUserConverter;
    private final UserToUserDboConverter userToUserDboConverter;

    @Override
    public User createUser(User user) {
        UserDbo userDbo = userToUserDboConverter.convert(user);
        userDbo = userJpaRepo.save(userDbo);
        return userDboToUserConverter.convert(userDbo);
    }

    @Override
    public boolean existsByEmail(String email) {
        return userJpaRepo.existsByEmail(email);
    }

    @Override
    public UserDbo findByEmail(String email) {
        return userJpaRepo.findByEmail(email);
    }

    @Override
    // generate OTP to the user's email
    public void generateOTPToUser(UserDbo user) {
        String otp = generateOTP();
        user.setOtp(otp);
        user.setOtpExpiration(LocalDateTime.now().plusMinutes(5)); // OTP expires in 5 minutes
        userJpaRepo.save(user);
    }

    @Override
    public void changePassword(UserDbo userDbo, byte[] newPassword) {
        userDbo.setHashedPassword(newPassword);
        userJpaRepo.save(userDbo);
    }

    public UserDbo findUserDboById (Long userId){
        return userJpaRepo.findUserDboById(userId);
    }

    // Generate a random OTP
    public String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000); // Generates a random integer between 100000 and 999999
        return String.valueOf(otp);
    }

}
