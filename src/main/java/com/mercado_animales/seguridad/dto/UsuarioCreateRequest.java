package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * Alta de usuario por parte del ADMIN.
 * Si no se envian roles se asigna COMPRADOR por defecto.
 */
@Getter
@Setter
public class UsuarioCreateRequest {

    @NotBlank(message = "el nombre es obligatorio")
    private String nombre;

    @NotBlank(message = "el email es obligatorio")
    @Email(message = "el email no tiene formato valido")
    private String email;

    @NotBlank(message = "la contrasena es obligatoria")
    @Size(min = 8, message = "la contrasena debe tener al menos 8 caracteres")
    private String password;

    private String telefono;

    private String ruc;

    private List<String> roles;

    private Boolean activo;
}
