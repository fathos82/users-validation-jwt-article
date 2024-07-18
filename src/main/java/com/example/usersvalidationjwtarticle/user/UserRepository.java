package com.example.usersvalidationjwtarticle.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<PersistentUser,  Long> {
    PersistentUser getPersistentUserByUserName(String userName);
}
