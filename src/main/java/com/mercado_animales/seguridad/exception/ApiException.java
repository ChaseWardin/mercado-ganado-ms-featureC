package com.mercado_animales.seguridad.exception;

import org.springframework.http.HttpStatus;

/**
 * Excepcion de negocio con el status HTTP que corresponde.
 *
 * <p>Reemplaza a los {@code RuntimeException} sueltos: el handler traduce el
 * status a la respuesta y el mensaje viaja tal cual al cliente, sin stacktrace.
 */
public class ApiException extends RuntimeException {

    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
