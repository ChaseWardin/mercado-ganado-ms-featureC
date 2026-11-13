package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * Reinicio de contrasena por parte de un ADMIN.
 *
 * <p>La clave la define el ADMIN y es temporal: el backend marca la cuenta con
 * {@code debeCambiarPassword = true} para que el usuario elija una nueva en su
 * proximo ingreso. No se pide la clave anterior porque el caso de uso es
 * justamente que el usuario la olvido.
 */
@Getter
@Setter
public class ReiniciarPasswordRequest {

    @NotBlank(message = "la contrasena de reinicio es obligatoria")
    @Size(min = 8, message = "la contrasena de reinicio debe tener al menos 8 caracteres")
    private String password;
}
