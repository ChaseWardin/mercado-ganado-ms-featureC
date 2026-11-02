package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * Cuerpo del DELETE /api/usuarios/{id}.
 *
 * <p>Dar de baja una cuenta ya no es un borrado logico anonimo: el
 * administrador debe explicar el motivo. Ese texto se guarda en
 * {@code usuarios.motivo_desactivacion} y es el que el login le muestra al
 * usuario cuando intenta ingresar.
 */
@Getter
@Setter
public class DesactivarUsuarioRequest {

    @NotBlank(message = "el motivo de la desactivacion es obligatorio")
    @Size(max = 500, message = "el motivo no puede superar los 500 caracteres")
    private String motivo;
}
