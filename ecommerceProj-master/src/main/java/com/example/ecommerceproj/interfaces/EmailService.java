package com.example.ecommerceproj.interfaces;
import com.example.ecommerceproj.usecase.EmailUsecase;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
@RequiredArgsConstructor
@Service
public class EmailService implements EmailUsecase {
    private final JavaMailSender javaMailSender;
    private final EmailService emailService;

    public void sendEmail(String to, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        javaMailSender.send(message);
    }

    //Send Confirmation Email
    public void sendConfirmationEmail(UserDbo user) {
        String to = user.getEmail();
        String subject = "Account Confirmation";
        String text = "Thank you for registering with our service!";
        emailService.sendEmail(to, subject, text);
    }
}




