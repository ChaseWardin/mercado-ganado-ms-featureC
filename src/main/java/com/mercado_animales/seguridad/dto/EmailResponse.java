package com.mercado_animales.seguridad.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class EmailResponse {
    private boolean enviado;
    private String mensaje;
}
