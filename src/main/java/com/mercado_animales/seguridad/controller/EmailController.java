package com.mercado_animales.seguridad.controller;

import com.mercado_animales.seguridad.dto.EmailRequest;
import com.mercado_animales.seguridad.dto.EmailResponse;
import com.mercado_animales.seguridad.service.EmailService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/emails")
public class EmailController {

    private final EmailService emailService;

    public EmailController(EmailService emailService) {
        this.emailService = emailService;
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('SERVICE', 'ADMIN')")
    @Operation(summary = "Envia un email (interno o ADMIN)")
    public ResponseEntity<EmailResponse> enviar(@Valid @RequestBody EmailRequest request) {
        emailService.enviar(request);
        return ResponseEntity.accepted().body(new EmailResponse(true, "Email encolado para envio"));
    }
}
