package com.example.ecommerceproj.usecase;

import com.example.ecommerceproj.interfaces.UserDbo;

public interface EmailUsecase {
    public void sendEmail(String to, String subject, String text);

    public void sendConfirmationEmail(UserDbo user);


}
