package com.alkan.securitydemov1.data.service;

import com.alkan.securitydemov1.data.dto.ClientDto;
import com.alkan.securitydemov1.data.entity.Client;
import com.alkan.securitydemov1.data.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class ClientService implements RegisteredClientRepository {
    private final ClientRepository repository;
    private final PasswordEncoder passwordEncoder;

    private Client clientFromDto(ClientDto dto) {
        return Client.builder()
                .clientId(dto.getClientId())
                .clientSecret(passwordEncoder.encode(dto.getClientSecret()))
                .authenticationMethods(dto.getAuthenticationMethods())
                .authorizationGrantTypes(dto.getAuthorizationGrantTypes())
                .redirectUris(dto.getRedirectUris())
                .scopes(dto.getScopes())
                .requireProofKey(dto.isRequireProofKey())
                .build();
    }

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = repository.findById(id)
                .orElseThrow(() -> new RuntimeException("client not found"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = repository.findByClientId(clientId)
                .orElseThrow(() -> new RuntimeException("client not found"));
        return Client.toRegisteredClient(client);
    }

    public Client save(ClientDto dto) {
        Client client = clientFromDto(dto);
        return repository.save(client);
    }
}
