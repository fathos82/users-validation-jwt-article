package com.example.usersvalidationjwtarticle.security;

import com.example.usersvalidationjwtarticle.user.PersistentUser;
import com.example.usersvalidationjwtarticle.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class SecurityUserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public SecurityUser loadUserByUsername(String username) throws UsernameNotFoundException {
        PersistentUser user = userRepository.getPersistentUserByUserName(username);

        if (user == null){
            throw new UsernameNotFoundException("not found");
        }
        return new SecurityUser(user);
    }
}
