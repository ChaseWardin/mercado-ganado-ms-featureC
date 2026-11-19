package com.mercado_animales.seguridad.service;

import com.mercado_animales.seguridad.dto.EmailRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Arma los correos de cada evento de seguridad.
 *
 * <p>Centralizar tipo, asunto y variables evita que cada llamador repita un
 * {@link EmailRequest} a mano y que dos pantallas manden el mismo aviso con
 * plantillas distintas. El envio real lo hace {@link EmailService}.
 */
@Service
@RequiredArgsConstructor
public class NotificacionService {

    private final EmailService emailService;

    /** Codigo para confirmar el registro de una cuenta nueva. */
    public void enviarVerificacion(String email, String nombre, String codigo) {
        enviar(email, "VERIFICACION_CODIGO", Map.of(
                "nombre", nombreSeguro(nombre),
                "codigo", codigo));
    }

    /** Codigo de un solo uso para recuperar la contrasena. */
    public void enviarRecuperacion(String email, String nombre, String codigo) {
        enviar(email, "RECUPERACION", Map.of(
                "nombre", nombreSeguro(nombre),
                "codigo", codigo));
    }

    /** Clave temporal definida por un ADMIN al crear o reiniciar una cuenta. */
    public void enviarCredenciales(String email, String nombre, String passwordTemporal) {
        enviar(email, "CREDENCIALES", Map.of(
                "nombre", nombreSeguro(nombre),
                "email", email,
                "password", passwordTemporal));
    }

    /** Aviso de baja con el motivo que cargo el ADMIN. */
    public void enviarCuentaBloqueada(String email, String nombre, String motivo) {
        enviar(email, "CUENTA_BLOQUEADA", Map.of(
                "nombre", nombreSeguro(nombre),
                "motivo", motivo == null || motivo.isBlank()
                        ? "Contacta a un administrador para mas informacion."
                        : motivo.trim()));
    }

    public void enviarCuentaReactivada(String email, String nombre) {
        enviar(email, "CUENTA_REACTIVADA", Map.of(
                "nombre", nombreSeguro(nombre)));
    }

    /** Correo de diagnostico para validar el SMTP desde la bandeja. */
    public void enviarPrueba(String email, String nombre) {
        enviar(email, "PRUEBA", Map.of(
                "nombre", nombreSeguro(nombre),
                "fecha", java.time.LocalDateTime.now().toString()));
    }

    /**
     * Mensaje libre que redacta un ADMIN desde la bandeja y elige a quien
     * mandarlo. El cuerpo es texto plano: la plantilla lo escapa y respeta los
     * saltos de linea, asi que no se inyecta HTML.
     */
    public void enviarPersonalizado(String email, String nombre, String asunto,
                                    String mensaje, String remitente) {
        enviar(email, "PERSONALIZADO", asunto, Map.of(
                "nombre", nombreSeguro(nombre),
                "asunto", asunto,
                "mensaje", mensaje,
                "remitente", remitente));
    }

    private void enviar(String email, String tipo, Map<String, Object> variables) {
        enviar(email, tipo, null, variables);
    }

    private void enviar(String email, String tipo, String asunto, Map<String, Object> variables) {
        EmailRequest req = new EmailRequest();
        req.setTo(List.of(email));
        req.setTipo(tipo);
        req.setSubject(asunto);
        req.setVariables(variables);
        emailService.enviar(req);
    }

    private String nombreSeguro(String nombre) {
        return nombre == null || nombre.isBlank() ? "usuario" : nombre.trim();
    }
}
