package com.alkan.securitydemov1.controller;

import com.alkan.securitydemov1.data.dto.ClientDto;
import com.alkan.securitydemov1.data.entity.Client;
import com.alkan.securitydemov1.data.service.ClientService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/clients")
@AllArgsConstructor
public class ClientController {
    private final ClientService service;

    @PostMapping("/save")
    public Client save(@RequestBody ClientDto dto) {
        return service.save(dto);
    }
}
