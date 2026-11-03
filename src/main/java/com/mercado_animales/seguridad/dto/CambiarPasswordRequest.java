package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * Cambio de contrasena del propio usuario autenticado.
 *
 * <p>La actual se exige siempre: un token filtrado no debe alcanzar para
 * apropiarse de la cuenta cambiandole la clave.
 */
@Getter
@Setter
public class CambiarPasswordRequest {

    @NotBlank(message = "la contrasena actual es obligatoria")
    private String passwordActual;

    @NotBlank(message = "la contrasena nueva es obligatoria")
    @Size(min = 8, message = "la contrasena nueva debe tener al menos 8 caracteres")
    private String passwordNueva;
}
