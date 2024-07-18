# Validação por Tokenização JWT seguindo boas práticas:
Olá, Dev! Se você esbarrou por aqui, deve estar cansado de pular de tutorial em tutorial tentando encontrar a forma correta de fazer autenticação com Spring seguindo boas práticas. Mas chega disso! Vou te mostrar neste post tudo que você precisa para construir uma validação por token seguindo as melhores práticas na arquitetura Spring!

### O que é validação por tokenização?

**Tokenização** é o processo de gerar um token (uma string única) que representa a identidade de um usuário e pode ser usado para acessar recursos protegidos. Com **JWT (JSON Web Token)**, um tipo de token, você pode armazenar informações sobre o usuário de forma segura e compacta. O JWT é amplamente usado devido à sua facilidade de uso e segurança.

### Configuração do projeto: Instalando dependências

Para criar o projeto, você pode utilizar o [Spring Initializer](https://start.spring.io/). Eu prefiro usar o Maven para gerenciar minhas dependências. Você precisará adicionar os seguintes módulos:

!https://prod-files-secure.s3.us-west-2.amazonaws.com/940820b4-5908-4f88-9e9f-f09fdd48ec45/0ca902ba-d82f-4949-946f-8004eed31cc6/Untitled.png

Para iniciar nosso projeto, utilizamos o Spring Initializr para configurar o ambiente de desenvolvimento. Selecionamos as dependências essenciais para nossa aplicação, incluindo Spring Web, Spring Data JPA, Postgres Driver e Spring Security. Essas tecnologias são fundamentais para o desenvolvimento de nossa solução, fornecendo recursos robustos para construção de APIs RESTful, acesso a banco de dados, autenticação e autorização seguras.

Nota: Eu escolhi o Postgres, mas você pode utilizar o banco de dados da sua preferência!

Além disso, você deve configurar seu banco de dados no `application.properties`. Ficará algo parecido com isso:

!https://prod-files-secure.s3.us-west-2.amazonaws.com/940820b4-5908-4f88-9e9f-f09fdd48ec45/68f09ebf-4516-4329-ab53-a7b47e14eb7f/Untitled.png

Não se esqueça de substituir pelas suas credenciais em: `url`, `username` e `password`.

### Camada de Configurações de Segurança: Limitando o acesso de rotas

Quando falamos de segurança, devemos limitar ao máximo o acesso de rotas delicadas até que o usuário esteja autenticado. Então, iniciamos permitindo o acesso à rota “/login”, que é a rota onde o usuário poderá realizar a autenticação. Vamos limitar o acesso às demais rotas.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
 @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{           
        httpSecurity.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(requestMatcherRegistry -> requestMatcherRegistry
                        .requestMatchers(HttpMethod.POST,"/login").permitAll() // QUALQUER UM ESTADO AUTORIZADO A ACESSAR ESSA PORTA
                        .anyRequest().authenticated()  // QUALQUER UM PRECISA ESTAR AUTENTCIADO PARA ACESSAR ESSA PORTA.
        return httpSecurity.build();
    }
```

**Nota:** Quando falamos de uma aplicação Spring Security, um passo crucial é definir o que cada tipo de usuário pode acessar. Por exemplo, em uma aplicação de gerenciamento de estoque: um administrador pode consultar os produtos em estoque, adicionar e remover produtos, listar os produtos, etc. Já um usuário comum poderia apenas consultar o estoque e listar os produtos disponíveis. Isso é feito através de **Roles**. Logo, farei uma postagem sobre isso.

Ótimo, com pouquíssimas linhas de código você limitou o acesso aos endpoints. Agora, qualquer usuário precisa ser validado. Visto isso, podemos partir para o próximo passo: que tal definir quem será o usuário da camada de segurança?

### Camada de Persistência: Definindo uma Entidade de Segurança

Toda aplicação precisa dos seus usuários salvos em um banco de dados. Você precisa checar as credenciais do seu usuário, mesmo na validação por token. O usuário precisa enviar as credenciais no primeiro acesso para fornecer um token de acesso. Então, começamos definindo uma entidade que será persistida em seu banco:

```java
@Table(name = "\"user\"")

@Entity
public class PersistentUser {
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;
    private String userName;
    private String password;
// Getters and Setters...
}

```

Pronto, você definiu uma entidade persistida no banco. Agora, bastante atenção nessa parte. O Spring oferece implementações prontas para validar seus usuários no banco. Isso é feito através de um `AuthenticationProvider`, mais especificamente um `DaoAuthenticationProvider`. Os providers na arquitetura do Spring Security são uma camada importante responsável por validar suas credenciais. Mas você não precisa saber isso para essa implementação. Futuramente, pretendo fazer um post detalhando as camadas do Spring Security. Como recomendação, deixo uma leitura: **Spring Security In Action**.

Esse `DaoAuthenticationProvider` irá validar seu usuário. Mas para isso, você precisa estar dentro do escopo do framework. O Spring não reconhecerá de cara o seu `PersistentUser`. Você precisará extender de uma interface chamada `UserDetails`, que é a entidade que o Spring reconhece. Mas como boa prática, recomendo separar as implementações criando mais uma entidade que vai extender dessa interface e lá dentro terá seu `PersistentUser`.

```java
public class SecurityUser implements UserDetails {
    private final PersistentUser persistentUser;
    public SecurityUser(PersistentUser persistentUser){
        this.persistentUser = persistentUser;
    }
    
    //Hoje não trataremos sobre Roles de acesso, por isso definimos apenas uma ROLE
   // "USER".
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

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

```

Definimos agora um `UserRepository`:

```java
@Repositorypublic interface UserRepository extends JpaRepository<PersistentUser, Long> {    PersistentUser getPersistentUserByUserName(String userName);}
```

Seguindo a lógica de se manter dentro do framework, agora precisamos definir uma classe de serviço para nosso `SecurityUser` que implementa uma interface `UserDetailsService`. Será essa classe que será usada pelo `AuthenticationProvider` para validar seu usuário.

// TALVER INSERIR TEXTO

```java
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

```

### PasswordEncoder: BCryptPassword

Você já deve saber que é uma prática salvar senhas no banco de dados com criptografia. Você deve especificar ao Spring qual será a classe de criptografia usada. Então, ainda em `SecurityConfig`:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
		// Emited Code...
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
```

Pronto! Definimos um `PersistentUser` e um `SecurityUser`. Agora estamos prontos para finalizar a primeira etapa: validar um login com username e password. Para isso, vamos usar um filtro de requisição.

### Filtros de Requisição: InitialAuthenticationFilter

A validação será feita através de um filtro de requisição. Esses filtros também fazem parte da arquitetura do Spring Security e seu objetivo básico é filtrar as requisições, validando ou invalidando a requisição. Imagine que são passos que uma requisição precisa passar para ser considerada segura pela aplicação. O Spring Security oferece flexibilidade para que você possa adicionar filtros personalizados.

Gosto sempre de ressaltar uma preferência pessoal minha: fazer a validação antes de dar acesso a qualquer controller da aplicação (endpoints) de fato. Mas isso não é uma regra e, em muitos casos, pode ser necessário autenticação na camada que será responsável por autenticar o usuário. Isso oferece vantagens como validação precoce antes de permitir acesso a qualquer outra camada.

Colocados os pontos, agora vamos criar nosso filtro inicial que irá validar as credenciais do nosso usuário para que o `DaoAuthenticationProvider` possa validá-lo.

```java
@Component
public class InitialAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    AuthenticationManager authenticationManager;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String username = request.getHeader("username");
        String password = request.getHeader("password");
        
        // Authenticando com Authentication Manager:
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authenticationResult =  authenticationManager.authenticate(authentication);
				
        // Adicionar mensagem na resposta:
            if (authenticationResult.isAuthenticated()) {
                request.setAttribute("message", "Autenticado com sucesso");
            } else {
                request.setAttribute("message", "Falha na autenticação");
            }
        
        filterChain.doFilter(request, response); // Pule para o proximo filtro

    }
}

```

Calma, calma! Esse `AuthenticationManager` não é nenhum bicho de sete cabeças. Veja bem, ele é a ponte entre a autenticação e os providers. Basicamente, ele vai distribuir a `Authentication` para os providers que irão validar a autenticação. Esse objeto `UsernamePasswordAuthenticationToken` é o tipo de autenticação que o `DaoAuthenticationProvider` reconhe

ce, ele será passado para ser validado pelo `UserDetailsService`.

Definimos o `AuthenticationManager` e configuramos nosso `InitialAuthenticationFilter` dentro do escopo da nossa configuração de segurança. A configuração deve ficar assim:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
		// Emited Code...
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
```

Você precisará adicionar também uma dependência para o filtro.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private InitialAuthenticationFilter initialAuthenticationFilter;
    // Emitted Code...
}

```

Finalmente, você vai adicionar o filtro na cadeia de filtros. Isso significa que qualquer requisição vai passar por ele primeiro.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private InitialAuthenticationFilter initialAuthenticationFilter;
    // Emitted Code...
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(requestMatcherRegistry -> requestMatcherRegistry
                        .requestMatchers(HttpMethod.POST, "/login").permitAll() // Qualquer um está autorizado a acessar essa rota
                        .anyRequest().authenticated()  // Qualquer um precisa estar autenticado para acessar outras rotas
                ).addFilterBefore(initialAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }
}

```

### Teste: Inserindo um usuário no banco

Para inserirmos um usuário fictício no banco, eu gosto de usar um `CommandLineRunner`. Isso porque o `CommandLineRunner` é um callback usado para realizar ações específicas ao iniciar a aplicação. Isso é útil para testes. Eu removo depois.

Crie a classe:

```java
@Component
public class InitialUserLoader implements CommandLineRunner {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        PersistentUser user = new PersistentUser();
        user.setUserName("Joao");
        user.setPassword(passwordEncoder.encode("12345678"));
        userRepository.save(user);
    }
}

```

Rodando a aplicação, você deverá ter o usuário salvo no banco. Para realizar o teste, utilizo o [Insomnia](https://insomnia.rest/) (um software muito bom, vale a pena conferir).

Faça uma requisição POST para `/login` e adicione os headers:

```
username : danilo
password : 12345
```

E você terá o seguinte resultado:

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/940820b4-5908-4f88-9e9f-f09fdd48ec45/7a10ac10-355a-4715-9487-c2b2527e68e9/7941ebe1-7ae9-4e6b-9be8-629baf28a81f.png)

Provavelmente você deverá receber um 403 (Forbidden) na resposta. Não se preocupe! Isso acontece porque o `InitialAuthenticationFilter` está autenticando, mas não retornamos um token.

Para isso, vamos adicionar a geração do token utilizando JWT.

### Utilizando JWT: Gerando e Validando Tokens

Primeiro, adicione a dependência JWT no seu `pom.xml`.

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

O JWT (JSON Web Token) requer uma chave secreta para gerar tokens exclusivos para a sua aplicação. Vamos configurar um serviço para gerenciar a geração e validação desses tokens.

```java
@Service
public class JwtService {

    private static final String SECRET_KEY = "EssaAplicaçãoTaDemaisParaCarambaViu";
    private static final long EXPIRATION_TIME_HRS = 3; // 3 horas

    public String generateToken(String username) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);

        return JWT.create()
                .withSubject(username) // Define o nome de usuário como subject do token
                .withExpiresAt(generateExpiresDate()) // Define a data de expiração do token
                .sign(algorithm); // Assina o token com o algoritmo especificado
    }
}
```

Vamos criar um o método `generateExpiresDate()`  que gera o tempo/data de expiração do nosso token considerando o fuso horário do Brasil:

```java
    @Service
public class JwtService {
   //Emited code...   
    private Instant generateExpiresDate() {
        ZoneId zoneId = ZoneId.of("America/Sao_Paulo"); // considera fuso-horario do brasil
        ZonedDateTime now = ZonedDateTime.now(zoneId); // pega o tempo de agora
        return now.plusHours(EXPIRATION_TIME_HRS).toInstant(); // define que ira expirar em 3 horas.
    }
}

```

Ótimo! estamos quase lá!

Agora precisamos criar uma classe que ira validar nosso token e caso ocorra tudo bem ira retornar o subject do token que no caso definimos como o usrename do usuario.

```java
       @Service
public class JwtService {
   //Emited code...   
   
   public String validateToken(String jwtoken) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            return JWT.require(algorithm) // ira retornar a classe que faz verificação
                    .withIssuer("user-validation-jwt-article")
                    .build().verify(jwtoken) // realiza a verificação
                    .getSubject(); // retorno o subject definido na criação do token, nesse caso o username do usuario!
        }
        // Caso algum das informações não estejam correta retornara um string vazia!
        catch (JWTVerificationException e) {
            System.out.println("Erro ao validar token");
            return "";
        }
    }
}
```

Agora, modifique o `InitialAuthenticationFilter` para gerar e retornar o token:

```java
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
        Authentication authenticationResult =  authenticationManager.authenticate(authentication);

        if (authenticationResult.isAuthenticated()){
            // RETORNAMOS O TOKEN.
            response.setHeader("Authorization", "Bearer "+jwtService.generateToken(username));
        }
        filterChain.doFilter(request, response); // Pule para o proximo filtro

    }
}
```

Entendeu isso??? parece confuso, um monte de codigo relacionado tokenização jwt, mas o detalhe aqui é que antes nos estávamos apenas usando Spring Security para validar o nosso `SecurityUser,`

agora o nosso filtro após validar nosso login, retornara nosso token pelo header:

![Captura de tela 2024-07-18 154300.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/940820b4-5908-4f88-9e9f-f09fdd48ec45/a311b004-10f2-4069-bcb5-df1f24a284d0/Captura_de_tela_2024-07-18_154300.png)

Guarde esse token, pois ele será necessário para acessar os endpoints protegidos.

### Validando o Token em Requisições: JwtAuthenticationFilter

Para validar o token em cada requisição, criaremos um filtro de autenticação:

```java
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
            System.out.println(authenticationValidated);
            // Adiciona authenticação validada no contexto do SpringSecurity
            SecurityContextHolder.getContext().setAuthentication(authenticationValidated);
        }
        filterChain.doFilter(request, response); // Pule para o proximo filtro

    }

```

Neste filtro, a nossa prioridade é garantir que o token JWT seja extraído corretamente do cabeçalho de autorização da requisição. Ao validar o token com segurança usando o serviço dedicado `JwtService` e carregar os detalhes do usuário através do `SecurityUserService`, asseguramos uma autenticação confiável. Ao estabelecer esta autenticação no contexto do Spring Security, proporcionamos ao usuário a tranquilidade de uma sessão segura e autenticada durante toda a interação com a aplicação.

Adicione este filtro à cadeia de filtros em `SecurityConfig`:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private InitialAuthenticationFilter initialAuthenticationFilter;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(requestMatcherRegistry -> requestMatcherRegistry
                        .requestMatchers(HttpMethod.POST,"/login").permitAll() // QUALQUER UM ESTADO AUTORIZADO A ACESSAR ESSA PORTA
                        .anyRequest().authenticated()  // QUALQUER UM PRECISA ESTAR AUTENTCIADO PARA ACESSAR ESSA PORTA.
                )
                .addFilterBefore(initialAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // Adicionando Novo Filtro JwtAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, InitialAuthenticationFilter.class);
        return httpSecurity.build();
    }
    // Emited Code...
}
```

Agora, suas requisições serão validadas usando o token JWT.

### Testando a Aplicação: É Hora de Comemorar!

Vamos criar agora um endpoint `/teste` em nossa controller para receber requisições e verificar se nosso sistema está autenticando corretamente os usuários. Veja como é simples:

```java
javaCopy code
@RestController
@RequestMapping("/teste")
public class TestController {

    @GetMapping
    public ResponseEntity<String> testeAcesso() {
        return ResponseEntity.ok("Você está autenticado!");
    }
}

```

É simples, não é mesmo? Se tudo estiver configurado corretamente, esta será uma ótima maneira de testar se a autenticação está funcionando como esperado. Vamos seguir os passos para verificar isso:

simples, não é mesmo? Se tudo estiver configurado corretamente, esta será uma ótima maneira de testar se a autenticação está funcionando como esperado. Vamos seguir os passos para verificar isso:

1. **Obtenha o Token**: Primeiro, faça o login para obter o token de acesso. A captura do token é essencial para verificar a autenticação posteriormente.

Exemplo:

![Captura de tela 2024-07-18 154300.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/940820b4-5908-4f88-9e9f-f09fdd48ec45/ebc10fef-e9dd-4217-a5d8-81c3fd94680a/08ae65e0-0099-495c-954c-df7adc9a3585.png)

1. **Adicione o Token**: Copie o token obtido e adicione-o ao cabeçalho de Authorization de sua requisição, utilizando o prefixo "Bearer " seguido pelo token.

Exemplo:

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/940820b4-5908-4f88-9e9f-f09fdd48ec45/06dcc768-e02b-4ffc-ba56-3c014d406804/Untitled.png)

1. **Acesso ao Endpoint `/teste`**: 

Agora, acesse o endpoint `/teste` enviando o token de acesso junto com a requisição.

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/940820b4-5908-4f88-9e9f-f09fdd48ec45/764c4798-73ed-493a-85e9-3c2d3366892f/Untitled.png)

Como você pode ver, tudo funcionou perfeitamente!

### Sim, Nem Tão Simples Assim...

Claro, pode não parecer tão simples assim à primeira vista. Você pode estar se perguntando sobre termos como `Providers`, `UserDetails`, `UserDetailsService`, `AuthenticationManager` e `SecurityContextHolder`. Mas não se preocupe, esses são componentes importantes do Spring Security, trabalhando juntos para garantir a segurança da sua aplicação.

Essas camadas do Spring Security são essenciais para autenticar usuários, gerenciar detalhes do usuário e manter o contexto de segurança durante uma sessão. Se você está interessado em entender mais sobre esses conceitos, recomendo dar uma olhada nos primeiros capítulos do livro "Spring Security in Action". E fique tranquilo, em breve abordaremos esses conceitos de forma mais detalhada aqui.

### Conclusão

Pronto! Agora você tem uma aplicação Spring configurada para autenticação JWT. Esse é um ponto de partida para implementar segurança robusta em suas aplicações. Espero que tenha ajudado!

Boa codificação! 🚀
