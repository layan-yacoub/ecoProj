package com.example.ecommerceproj.controller;

import com.example.ecommerceproj.domain.User;
import com.example.ecommerceproj.interfaces.*;
import com.example.ecommerceproj.usecase.UserUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping(path = "api/user")
public class RegisterUserController {
    private final UserUseCase userUseCase;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody RegisterUserResponseDto requestDto) {
        // Convert requestDto to User;
        User user = RegisterUserDtoToUserConverter.convertToUser(requestDto);
        // Register the user
        User registeredUser = userUseCase.register(user);

        if (registeredUser != null) {
            return ResponseEntity.ok("");
        } else {
            return ResponseEntity.badRequest().body("");
        }
    }
    @PostMapping("/sendOTP")
    public ResponseEntity<String> sendOTP(@RequestParam String email){
    //send OTP by email
    userUseCase.sendOTPByEmail(email);
    return ResponseEntity.ok().body("");
    }
    @GetMapping("/confirm/OTP")
    public ResponseEntity<String> confirmOTP(@RequestParam String email, String otp) {
        try {
            userUseCase.confirmOTP(email, otp);
            return ResponseEntity.ok().body("OTP confirmed successfully");
        } catch (OTPValidationException e) {
            return ResponseEntity.badRequest().body("OTP validation failed: " + e.getMessage());
        }
    }
    @PostMapping("/login") // if the password in not correct it will give you message and if the email is not correct it will give you a bad request
    public ResponseEntity<String> login (@RequestBody RequestLoginDto requestLoginDto){
        if (!userUseCase.existsByEmail(requestLoginDto.getEmail()))
            return ResponseEntity.badRequest().body("");

           boolean password = userUseCase.loginConfirmation(requestLoginDto.getEmail(),requestLoginDto.getHashedPassword());
            if (password)
             return ResponseEntity.ok("");
            else
            return ResponseEntity.badRequest().body("Wrong password , please try again " );
    }
    @PostMapping("/forgetPass")
    public ResponseEntity<String> forgetPass(@RequestParam String email){
       //send OTP by email
       userUseCase.sendOTPByEmail(email);
       return ResponseEntity.ok().body("");
    }
    @PostMapping("/changePass")
    public ResponseEntity<String> changePass(@RequestParam String email, @RequestParam Integer otp , @RequestParam byte[] newPassword){
    //send OTP by email
        try {userUseCase.sendOTPByEmail(email);
        userUseCase.changePassword(email,newPassword);
        return ResponseEntity.ok("");
        } catch (OTPValidationException e) {
            return ResponseEntity.badRequest().body("OTP validation failed: " + e.getMessage());
        }}}

