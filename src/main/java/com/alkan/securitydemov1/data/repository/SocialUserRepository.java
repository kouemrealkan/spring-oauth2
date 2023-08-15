package com.alkan.securitydemov1.data.repository;

import com.alkan.securitydemov1.data.entity.SocialUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SocialUserRepository extends JpaRepository<SocialUser, String> {
    Optional<SocialUser> findByEmail(String email);
}
