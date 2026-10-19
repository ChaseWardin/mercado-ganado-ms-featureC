package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class EmailRequest {
    @NotEmpty
    private List<String> to;
    private String subject;
    private String tipo; // VERIFICACION, COMPRA, VENTA, CANCELACION, CONTACTO, ...
    private Map<String, Object> variables;
    private String html; // opcional: cuerpo HTML directo (sin plantilla)
}
