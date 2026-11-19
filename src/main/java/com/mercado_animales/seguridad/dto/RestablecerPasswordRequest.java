package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RestablecerPasswordRequest {
    @NotBlank @Email
    private String email;

    @NotBlank
    @Pattern(regexp = "\\d{6}", message = "El codigo debe tener 6 digitos")
    private String codigo;

    @NotBlank
    @Size(min = 8, max = 72, message = "La contrasena debe tener entre 8 y 72 caracteres")
    private String passwordNueva;
}
