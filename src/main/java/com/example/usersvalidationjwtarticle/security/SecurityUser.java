package com.example.usersvalidationjwtarticle.security;

import com.example.usersvalidationjwtarticle.user.PersistentUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

public class SecurityUser implements UserDetails {
    private final PersistentUser persistentUser;
    public SecurityUser(PersistentUser persistentUser){
        this.persistentUser = persistentUser;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("USER"));
    }

    @Override
    public String getPassword() {
        return this.persistentUser.getPassword();

    }

    @Override
    public String getUsername() {
        return this.persistentUser.getUserName();
    }
}
