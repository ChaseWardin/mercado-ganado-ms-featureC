package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * Edicion del propio perfil (usuario autenticado).
 *
 * <p>No incluye email a proposito: es el identificador de login y cambiarlo
 * exigiria volver a verificar la cuenta. Tampoco incluye roles ni activo.
 */
@Getter
@Setter
public class PerfilUpdateRequest {

    @NotBlank(message = "el nombre es obligatorio")
    private String nombre;

    private String telefono;

    private String ruc;
}
