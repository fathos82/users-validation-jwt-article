package com.example.usersvalidationjwtarticle.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    SecurityUserService securityUserService;
    @Autowired
    JwtService jwtService;

    // Essa função pegara o campo de Authorization do cabeçalho
    // e ira remover o "Bearer " deixando apenas o token bruto.
    private String extractTokenFromRequest(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return  bearerToken.substring(7);
        }
        return null;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwtToken = extractTokenFromRequest(request);
        if (jwtToken!= null){
            String userName = jwtService.validateToken(jwtToken);
            UserDetails securityUser = securityUserService.loadUserByUsername(userName);

            // Criamos uma authenticação validada:
            Authentication authenticationValidated = new UsernamePasswordAuthenticationToken(securityUser.getUsername(), null, securityUser.getAuthorities());
            // Adiciona authenticação validada no contexto do SpringSecurity
            SecurityContextHolder.getContext().setAuthentication(authenticationValidated);
        }
        filterChain.doFilter(request, response); // Pule para o proximo filtro

    }
}
