package com.example.usersvalidationjwtarticle.teste;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("teste")
public class TestController {
    @GetMapping
    public ResponseEntity<String> testeAcesso() {
        return ResponseEntity.ok("Voce esta autenticado!!!!");
    }
}
