package com.example.ecommerceproj.interfaces;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserJpaRepo extends JpaRepository<UserDbo, Long> {
    boolean existsByEmail(String email);
    UserDbo findByEmail (String email);
    UserDbo findUserDboById(Long userId);

}