package com.mercado_animales.seguridad.dto;

import java.util.List;

/** Pagina de correos con el mismo formato que usa la tabla de usuarios. */
public record PaginaEmails(List<EmailEnviadoResponse> content, long totalElements,
                           int totalPages, int number, int size) {
}
