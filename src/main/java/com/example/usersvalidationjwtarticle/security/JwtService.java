package com.example.usersvalidationjwtarticle.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

@Service
public class JwtService {
    private String SECRET_KEY = "EssaAplicaçãoTaDemaisParaCarambaViu";
    private final String ISSUER ="user-validation-jwt-article";
    private static final long EXPIRATION_TIME_HRS = 3; // 3 horas

    public String generateToken(String username) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);

        return JWT.create()
                .withSubject(username) // Define o nome de usuário como subject do token
                .withExpiresAt(generateExpiresDate()) // Define a data de expiração do token
                .sign(algorithm); // Assina o token com o algoritmo especificado
    }

    private Instant generateExpiresDate() {
        ZoneId zoneId = ZoneId.of("America/Sao_Paulo"); // considera fuso-horario do brasil
        ZonedDateTime now = ZonedDateTime.now(zoneId); // pega o tempo de agora
        return now.plusHours(EXPIRATION_TIME_HRS).toInstant(); // define que ira expirar em 3 horas.
    }

    public String validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            return JWT.require(algorithm) // ira retornar a classe que faz verificação
                    .withIssuer(ISSUER)
                    .build().verify(token) // realiza a verificação
                    .getSubject(); // retorno o subject definido na criação do token, nesse caso o username do usuario!
        }
        // Caso algum das informações não estejam correta retornara um string vazia!
        catch (JWTVerificationException e) {
            System.out.println("Erro ao validar token");
            return "";
        }
    }



}
