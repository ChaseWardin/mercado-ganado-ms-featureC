package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * Edicion completa de un usuario por parte del ADMIN.
 * Los roles se siguen gestionando con los endpoints /roles/{rol}.
 */
@Getter
@Setter
public class UsuarioUpdateRequest {

    @NotBlank(message = "el nombre es obligatorio")
    private String nombre;

    @NotBlank(message = "el email es obligatorio")
    @Email(message = "el email no tiene formato valido")
    private String email;

    private String telefono;

    private String ruc;

    private Boolean activo;
}
