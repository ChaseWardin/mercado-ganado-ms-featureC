package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RegistroRequest {
    @NotBlank
    private String nombre;
    @NotBlank @Email
    private String email;
    @NotBlank
    private String password;
    private String telefono;
    private String ruc;
}
