package com.mercado_animales.seguridad.controller;

import com.mercado_animales.seguridad.dto.PerfilUpdateRequest;
import com.mercado_animales.seguridad.dto.UsuarioCreateRequest;
import com.mercado_animales.seguridad.dto.UsuarioUpdateRequest;
import com.mercado_animales.seguridad.exception.ApiException;
import com.mercado_animales.seguridad.security.UsuarioAutenticado;
import com.mercado_animales.seguridad.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/usuarios")
@RequiredArgsConstructor
@Tag(name = "Usuarios", description = "Gestion de usuarios (ADMIN) y perfil propio")
public class UsuarioController {

    private final AuthService authService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Listar usuarios")
    public ResponseEntity<?> listar(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String nombre,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String rol,
            @RequestParam(required = false) Boolean activo) {
        return ResponseEntity.ok(authService.listarUsuarios(page, size, nombre, email, rol, activo));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Crear usuario")
    public ResponseEntity<?> crear(@Valid @RequestBody UsuarioCreateRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.crearUsuario(request));
    }

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Obtener mi perfil")
    public ResponseEntity<?> miPerfil(Authentication authentication) {
        return ResponseEntity.ok(authService.getByEmail(principal(authentication).getEmail()));
    }

    @PutMapping("/me")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Actualizar mi perfil (nombre, telefono y ruc)")
    public ResponseEntity<?> actualizarMiPerfil(@Valid @RequestBody PerfilUpdateRequest request,
                                                Authentication authentication) {
        return ResponseEntity.ok(authService.actualizarPerfil(principal(authentication).getId(), request));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @usuarioSecurity.esPropietario(#id, authentication)")
    @Operation(summary = "Obtener usuario por id (ADMIN o el propio usuario)")
    public ResponseEntity<?> getById(@PathVariable Integer id) {
        return ResponseEntity.ok(authService.getById(id));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Actualizar usuario (ADMIN)")
    public ResponseEntity<?> actualizar(@PathVariable Integer id,
                                        @Valid @RequestBody UsuarioUpdateRequest request) {
        return ResponseEntity.ok(authService.actualizarUsuario(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Desactivar usuario")
    public ResponseEntity<?> desactivar(@PathVariable Integer id) {
        return ResponseEntity.ok(authService.desactivar(id));
    }

    @PostMapping("/{id}/roles/{rol}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Asignar rol")
    public ResponseEntity<?> asignarRol(@PathVariable Integer id, @PathVariable String rol) {
        return ResponseEntity.ok(authService.asignarRol(id, rol));
    }

    @DeleteMapping("/{id}/roles/{rol}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Quitar rol")
    public ResponseEntity<?> quitarRol(@PathVariable Integer id, @PathVariable String rol) {
        return ResponseEntity.ok(authService.quitarRol(id, rol));
    }

    private UsuarioAutenticado principal(Authentication authentication) {
        if (authentication.getPrincipal() instanceof UsuarioAutenticado usuario) {
            return usuario;
        }
        // El token interno (ROLE_SERVICE) no representa a una persona.
        throw new ApiException(HttpStatus.FORBIDDEN,
                "Operacion no disponible para este tipo de credencial");
    }
}
