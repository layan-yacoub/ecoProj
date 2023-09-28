package com.example.ecommerceproj;

import com.example.ecommerceproj.auth.AuthenticationService;
import com.example.ecommerceproj.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.example.ecommerceproj.interfaces.Role.ADMIN;

@SpringBootApplication
public class EcommerceProjApplication {

	public static void main(String[] args) {
		SpringApplication.run(EcommerceProjApplication.class, args);
	}
	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService service
	) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstName("Admin")
					.lastName("Admin")
					.email("layanyacoub2001@gmail.com")
					.password("2023".getBytes())
					.role(ADMIN)
					.build();
			System.out.println("Admin token: " + service.register(admin).getAccessToken());


		};
	}
}