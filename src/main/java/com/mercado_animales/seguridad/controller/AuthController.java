package com.mercado_animales.seguridad.controller;

import com.mercado_animales.seguridad.dto.LoginRequest;
import com.mercado_animales.seguridad.dto.RegistroRequest;
import com.mercado_animales.seguridad.dto.VerificarRegistroRequest;
import com.mercado_animales.seguridad.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Autenticacion", description = "Login y registro con verificacion por email")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    @Operation(summary = "Iniciar sesion")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        AuthService.TokenResponse resp = authService.login(request.getEmail(), request.getPassword());
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/registro/vendedor")
    @Operation(summary = "Iniciar registro de vendedor")
    public ResponseEntity<?> iniciarRegistroVendedor(@Valid @RequestBody RegistroRequest request) {
        String mensaje = authService.iniciarRegistroVendedor(
                request.getEmail(), request.getNombre(), request.getPassword(),
                request.getTelefono(), request.getRuc());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("mensaje", mensaje, "email", request.getEmail()));
    }

    @PostMapping("/registro/comprador")
    @Operation(summary = "Iniciar registro de comprador")
    public ResponseEntity<?> iniciarRegistroComprador(@Valid @RequestBody RegistroRequest request) {
        String mensaje = authService.iniciarRegistroComprador(
                request.getEmail(), request.getNombre(), request.getPassword(),
                request.getTelefono(), request.getRuc());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("mensaje", mensaje, "email", request.getEmail()));
    }

    @PostMapping("/verificar-registro")
    @Operation(summary = "Verificar registro con codigo")
    public ResponseEntity<?> verificarRegistro(@Valid @RequestBody VerificarRegistroRequest request) {
        AuthService.TokenResponse resp = authService.confirmarRegistro(request);
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/activar-vendedor")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Activar rol vendedor")
    public ResponseEntity<?> activarVendedor(@RequestParam Integer usuarioId) {
        AuthService.TokenResponse resp = authService.activarRolVendedor(usuarioId);
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/activar-comprador")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Activar rol comprador")
    public ResponseEntity<?> activarComprador(@RequestParam Integer usuarioId) {
        AuthService.TokenResponse resp = authService.activarRolComprador(usuarioId);
        return ResponseEntity.ok(resp);
    }
}
