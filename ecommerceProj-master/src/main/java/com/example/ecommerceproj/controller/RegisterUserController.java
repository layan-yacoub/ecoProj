package com.example.ecommerceproj.controller;

import com.example.ecommerceproj.auth.AuthenticationRequest;
import com.example.ecommerceproj.auth.AuthenticationResponse;
import com.example.ecommerceproj.auth.AuthenticationService;
import com.example.ecommerceproj.auth.RegisterRequest;
import com.example.ecommerceproj.config.JwtService;
import com.example.ecommerceproj.domain.User;
import com.example.ecommerceproj.interfaces.*;
import com.example.ecommerceproj.usecase.UserUseCase;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;

@RestController
@AllArgsConstructor
@RequestMapping("api/v1/auth")
public class RegisterUserController {
    private final UserUseCase userUseCase;
    //private UserInfoService service;
    private JwtService jwtService;
    private AuthenticationManager authenticationManager;
    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) { // Convert requestDto to User;
        User user = RegisterUserDtoToUserConverter.convertToUser(request);
        // Register the user
        User registeredUser = userUseCase.register(user);

        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request, response);
    }

    /*  @PostMapping("/register")
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
      }*/
    @PostMapping("/sendOTP")
    public ResponseEntity<String> sendOTP(@RequestParam String email) throws UserNotFoundException {
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
        } catch (UserNotFoundException e) {
            throw new RuntimeException(email);
        }
    }

   /* @PostMapping("/login")
    // if the password in not correct it will give you message and if the email is not correct it will give you a bad request
    public ResponseEntity<String> login(@RequestBody RequestLoginDto requestLoginDto) {
        if (!userUseCase.existsByEmail(requestLoginDto.getEmail()))
            return ResponseEntity.badRequest().body("");

        boolean password = userUseCase.loginConfirmation(requestLoginDto.getEmail(), requestLoginDto.getHashedPassword());
        if (password)
            return ResponseEntity.ok("");
        else
            return ResponseEntity.badRequest().body("Wrong password , please try again ");
    }*/

    @PostMapping("/forgetPass")
    public ResponseEntity<String> forgetPass(@RequestParam String email) {
        //send OTP by email
        try {
            userUseCase.sendOTPByEmail(email);
        } catch (UserNotFoundException e) {
            throw new RuntimeException(e);
        }
        return ResponseEntity.ok().body("");
    }

    @PutMapping("/changePass")
    public ResponseEntity<String> changePass(@RequestParam String email, @RequestParam Integer otp, @RequestParam byte[] newPassword) {
        //change password
        try {
            userUseCase.changePassword(email, newPassword);
            return ResponseEntity.ok("");
        } catch (OTPValidationException e) {
            return ResponseEntity.badRequest().body("OTP validation failed: " + e.getMessage());
        }
    }

}

