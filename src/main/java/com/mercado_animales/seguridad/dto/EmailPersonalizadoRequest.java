package com.mercado_animales.seguridad.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

/**
 * Correo libre redactado por un ADMIN desde la bandeja.
 *
 * <p>No usa plantilla de evento: el asunto y el mensaje los escribe la persona.
 * El mensaje es texto plano y el HTML lo arma {@code personalizado.html}, que
 * escapa el contenido con Thymeleaf.
 */
@Data
public class EmailPersonalizadoRequest {

    @NotEmpty(message = "Elegí al menos un destinatario")
    @Size(max = 100, message = "No se pueden elegir más de 100 destinatarios por envío")
    private List<Integer> usuarioIds;

    @NotBlank(message = "El asunto es obligatorio")
    @Size(max = 150, message = "El asunto no puede superar los 150 caracteres")
    private String asunto;

    @NotBlank(message = "El mensaje es obligatorio")
    @Size(max = 4000, message = "El mensaje no puede superar los 4000 caracteres")
    private String mensaje;
}
