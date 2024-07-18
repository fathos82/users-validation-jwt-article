package com.example.usersvalidationjwtarticle.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class InitialAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService; // INJETAMOS AUTHENTICATION SERVICE NA VARIAVEL

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String username = request.getHeader("username");
        String password = request.getHeader("password");
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authenticationResult = authenticationManager.authenticate(authentication);


        if (authenticationResult.isAuthenticated()){
            // RETORNAMOS O TOKEN.
            response.setHeader("Authorization", "Bearer "+jwtService.generateToken(username));
        }
        filterChain.doFilter(request, response); // Pule para o proximo filtro

    }
}
