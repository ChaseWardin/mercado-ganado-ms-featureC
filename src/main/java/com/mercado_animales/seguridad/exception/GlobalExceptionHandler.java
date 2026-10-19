package com.mercado_animales.seguridad.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.List;

/**
 * Traduce excepciones a respuestas claras y sin detalles internos.
 * En particular, un login invalido deja de responder 500 y pasa a 401.
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> api(ApiException ex, HttpServletRequest req) {
        log.warn("{} - {} {}", ex.getStatus().value(), req.getMethod(), ex.getMessage());
        return ResponseEntity.status(ex.getStatus())
                .body(new ApiError(ex.getStatus().value(), ex.getStatus().name(),
                        ex.getMessage(), List.of(), req.getRequestURI()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> validacion(MethodArgumentNotValidException ex, HttpServletRequest req) {
        List<String> detalles = ex.getBindingResult().getFieldErrors().stream()
                .map(this::describir)
                .toList();
        return ResponseEntity.badRequest()
                .body(new ApiError(400, "BAD_REQUEST", "Datos invalidos", detalles, req.getRequestURI()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> cuerpoIlegible(HttpMessageNotReadableException ex, HttpServletRequest req) {
        return ResponseEntity.badRequest()
                .body(new ApiError(400, "BAD_REQUEST", "El cuerpo de la peticion no es valido",
                        List.of(), req.getRequestURI()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> argumentoInvalido(IllegalArgumentException ex, HttpServletRequest req) {
        return ResponseEntity.badRequest()
                .body(new ApiError(400, "BAD_REQUEST", ex.getMessage(), List.of(), req.getRequestURI()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> denegado(AccessDeniedException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiError(403, "FORBIDDEN", "No tienes permisos para esta operacion",
                        List.of(), req.getRequestURI()));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiError> noEncontrado(NoResourceFoundException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiError(404, "NOT_FOUND", "Recurso no encontrado",
                        List.of(), req.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> inesperado(Exception ex, HttpServletRequest req) {
        // Se registra completo en el log, pero al cliente solo va un mensaje generico.
        log.error("Error no controlado en {} {}", req.getMethod(), req.getRequestURI(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError(500, "INTERNAL_ERROR", "Error interno del servidor",
                        List.of(), req.getRequestURI()));
    }

    private String describir(FieldError error) {
        return error.getField() + ": " + error.getDefaultMessage();
    }
}
