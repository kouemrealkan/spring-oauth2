package com.alkan.securitydemov1.security;

import com.alkan.securitydemov1.data.repository.SocialUserRepository;
import com.alkan.securitydemov1.data.service.ClientService;
import com.alkan.securitydemov1.federated.FederatedIdentityConfigurer;
import com.alkan.securitydemov1.federated.UserRepositoryOAuth2UserHandler;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final SocialUserRepository socialUserRepository;

    private final ClientService clientService;

    @Bean
    @Order(1)
    public SecurityFilterChain webFilterChainForOauth(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.cors(Customizer.withDefaults());
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
        httpSecurity.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        httpSecurity.apply(new FederatedIdentityConfigurer());
        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appSecurity(HttpSecurity security) throws Exception {
        security.cors(Customizer.withDefaults());
        FederatedIdentityConfigurer federatedIdentityConfigurer = new FederatedIdentityConfigurer()
                .oauth2UserHandler(new UserRepositoryOAuth2UserHandler(socialUserRepository));
        security
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/auth/**", "/client/**", "/login").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .apply(federatedIdentityConfigurer);
        security.logout().logoutSuccessUrl("http://127.0.0.1:4200/logout");
        security.csrf().ignoringRequestMatchers("/auth/**", "/client/**");
        return security.build();
        /*  security.csrf().disable();
        security.authorizeHttpRequests(
                request ->
                        request.requestMatchers("/clients/**").permitAll()
                                .anyRequest().authenticated()).formLogin(Customizer.withDefaults());
        return security.build();

       */
    }

   /* @Bean
    public UserDetailsService userDetailsService() {
        var usr = User.withUsername("emre").password("12345").authorities("read").build();
        var usr2 = User.withUsername("yunus").password("123456").authorities("read").build();
        return new InMemoryUserDetailsManager(usr, usr2);
    }

    */

    /*
    OAuth 2.0 ve OpenID Connect protokollerinde,
    bir istemci uygulaması kimlik sağlayıcı üzerinden
    bir kullanıcının kimliğini doğrulamak ve yetkilendirmek istediğinde,
    önceden kaydedilmiş istemci bilgilerine ihtiyaç vardır.
    Bu istemci bilgileri, istemci uygulamasının
    kimlik sağlayıcıya nasıl bağlanacağını ve kimlik doğrulama ve
    yetkilendirme işlemlerini nasıl gerçekleştireceğini belirtir.

    Bu istemci bilgileri, genellikle "Registered Client" (Kayıtlı İstemci) olarak adlandırılır ve
    bir veritabanında veya bir depolama mekanizmasında saklanır.
    Bu depolama mekanizması, istemci uygulamalarının erişim
     yetkilendirme kodları, token'lar ve diğer güvenlik unsurlarını güvenli bir şekilde yönetmesini sağlar.
     */
   /* @Bean
    public RegisteredClientRepository registeredClientRepository() {
        var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("public-client-app")
                .clientSecret(passwordEncoder().encode("secret"))
                .scope(OidcScopes.OĞP)
                .redirectUri("https://oauthdebugger.com/debug")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grantType -> {
                    grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
                    grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                })
                .clientSettings(ClientSettings.builder().requireProofKey(true).build()).build();
        return new InMemoryRegisteredClientRepository(registeredClient);

    }

    */

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();
            if (context.getTokenType().getValue().equals("id_token")) {
                context.getClaims().claim("token_type", "id_token");
            }
            if (context.getTokenType().getValue().equals("access_token")) {
                context.getClaims().claim("token_type", "access_token");
                List<String> authorities = principal.getAuthorities()
                        .stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
                context.getClaims().claim("authorities", authorities).claim("username", principal.getName());
            }
        };
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    /*@Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

     */

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8080")
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var keys = generator.generateKeyPair();
        var publicKey = (RSAPublicKey) keys.getPublic();
        var privateKey = (RSAPrivateKey) keys.getPrivate();

        var rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // http://localhost:8080/oauth2/authorize?client_id=public-client-app&response_type=code&scope=openid&redirect_uri=http://127.0.0.1:8083/login/oauth2/code/public-client-app&code_challenge=YiFtM6O4kxc1PUVYiD1IauxYzbYMDO1cWFOdnC5c_5s&code_challenge_method=S256

    // http://localhost:8080/oauth2/authorize?client_id=public-client-app&response_type=code&scope=openid&redirect_uri=http://127.0.0.1:8083/login/oauth2/code/public-client-app&code_challenge=4rDN7gb128OwOD8KqjyNJNY5a_TUS9XOJy6070r-fOk&code_challenge_method=S256

    //http://127.0.0.1:8083/login/oauth2/code/public-client-app?code=1jaetui-KHgkhzMcqd3F1ItBNtW0JCFfzQP2hRwH61VIfe0PwMJ1tGP0TEhryc1PF8v22UIvC8iN3nt2GD1Fnnl7R3iorwZDbsHm9kbGoTtkQN9dBl0QQUTT-dtGXggW
}
