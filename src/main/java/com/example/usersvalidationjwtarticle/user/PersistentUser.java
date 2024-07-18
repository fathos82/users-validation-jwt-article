package com.example.usersvalidationjwtarticle.user;

import jakarta.persistence.*;

@Table(name = "\"user\"")

@Entity
public class PersistentUser {
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;
    private String userName;
    private String password;

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public String getPassword() {
        return password;
    }

    public String getUserName() {
        return userName;
    }
}
