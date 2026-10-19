package com.mercado_animales.seguridad.exception;

import java.util.List;

/**
 * Cuerpo de error uniforme del microservicio de seguridad.
 * Mismo contrato que vendedores/compras para que la UI lo lea igual.
 */
public record ApiError(int status, String code, String message, List<String> details, String path) {
}
