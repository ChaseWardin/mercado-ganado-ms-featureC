package com.mercado_animales.seguridad.dto;

import lombok.Data;

import java.time.LocalDateTime;

/**
 * Fila de la bandeja de correos.
 *
 * <p>En el listado {@code html} viaja en null para no mandar cuerpos completos
 * en cada pagina; el detalle ({@code GET /api/emails/{id}}) si lo trae.
 */
@Data
public class EmailEnviadoResponse {
    private Integer id;
    private String destinatarios;
    private String asunto;
    private String tipo;
    private String estado;
    private String error;
    private LocalDateTime creadoEn;
    private LocalDateTime enviadoEn;
    private String html;
}
