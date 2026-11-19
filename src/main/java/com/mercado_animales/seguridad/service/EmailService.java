package com.mercado_animales.seguridad.service;

import com.mercado_animales.notificacion.EmailEnviado;
import com.mercado_animales.notificacion.EstadoEmail;
import com.mercado_animales.seguridad.dto.EmailRequest;
import com.mercado_animales.seguridad.repository.EmailEnviadoRepository;
import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Unico emisor de correos de la plataforma.
 *
 * <p>El envio sigue siendo asincrono: quien llama recibe "encolado" y no espera
 * al SMTP. La diferencia es que ahora cada intento queda en
 * {@code emails_enviados}, con su estado final. Si Gmail rechaza el mensaje, la
 * bandeja lo muestra como FALLIDO en lugar de dejarlo escondido en el log.
 *
 * <p>El HTML que se guarda nunca lleva secretos: los codigos de verificacion y
 * las claves temporales se reemplazan por puntos antes de persistir.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    /** Variables cuyo valor no debe quedar guardado en la bandeja. */
    private static final Set<String> CLAVES_SECRETAS =
            Set.of("codigo", "password", "passwordtemporal", "clave");

    private static final String MASCARA = "******";

    private final JavaMailSender mailSender;
    private final Optional<TemplateEngine> templateEngine;
    private final EmailEnviadoRepository emailEnviadoRepository;

    @Value("${app.mail.from}")
    private String from;

    @Value("${spring.mail.host:}")
    private String mailHost;

    @Value("${spring.mail.port:}")
    private String mailPort;

    @Value("${spring.mail.username:}")
    private String mailUsername;

    @Value("${spring.mail.password:}")
    private String mailPassword;

    @PostConstruct
    public void mostrarConfiguracion() {
        log.info("SMTP host='{}', port='{}', username='{}', passwordLength={}",
                mailHost, mailPort, mailUsername,
                mailPassword == null ? 0 : mailPassword.length());
        if (mailHost == null || mailHost.isBlank() || "smtp.gmail.com".equals(mailHost)) {
            log.warn("MAIL_HOST no definido o sigue apuntando a Gmail por defecto. Revisa las variables de entorno.");
        }
        if (mailUsername == null || mailUsername.isBlank()) {
            log.warn("MAIL_USERNAME vacio: la autenticacion SMTP va a fallar.");
        }
    }

    @Async
    public void enviar(EmailRequest req) {
        String html = renderizar(req);
        String asunto = resolverAsunto(req);
        EmailEnviado registro = registrarIntento(req, asunto, html);

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            helper.setFrom(from);
            helper.setTo(req.getTo().toArray(new String[0]));
            helper.setSubject(asunto);
            helper.setText(html, true);
            mailSender.send(message);

            if (registro != null) {
                registro.setEstado(EstadoEmail.ENVIADO);
                registro.setEnviadoEn(LocalDateTime.now());
                actualizar(registro);
            }
            log.info("Email enviado a {} (tipo={})", req.getTo(), req.getTipo());
        } catch (Exception e) {
            log.error("Fallo al enviar email a {}: {}", req.getTo(), e.getMessage(), e);
            if (registro != null) {
                registro.setEstado(EstadoEmail.FALLIDO);
                registro.setError(recortar(mensajeDe(e), 1000));
                actualizar(registro);
            }
        }
    }

    /**
     * Guarda el intento antes de tocar el SMTP. Si la base falla, el correo se
     * manda igual: la bandeja es diagnostico, no un requisito para notificar.
     */
    private EmailEnviado registrarIntento(EmailRequest req, String asunto, String html) {
        try {
            EmailEnviado registro = new EmailEnviado();
            registro.setDestinatarios(String.join(", ", req.getTo()));
            registro.setAsunto(recortar(asunto, 255));
            registro.setTipo(req.getTipo());
            registro.setEstado(EstadoEmail.PENDIENTE);
            registro.setHtml(enmascarar(html, req.getVariables()));
            registro.setCreadoEn(LocalDateTime.now());
            return emailEnviadoRepository.save(registro);
        } catch (Exception e) {
            log.warn("No se pudo registrar el correo en la bandeja: {}", e.getMessage());
            return null;
        }
    }

    private void actualizar(EmailEnviado registro) {
        try {
            emailEnviadoRepository.save(registro);
        } catch (Exception e) {
            log.warn("No se pudo actualizar el estado del correo {}: {}",
                    registro.getId(), e.getMessage());
        }
    }

    private String renderizar(EmailRequest req) {
        String html = req.getHtml();
        if (html != null && !html.isBlank()) {
            return html;
        }

        String template = req.getTipo() == null ? "generic" : req.getTipo().toLowerCase(Locale.ROOT);
        if (templateEngine.isEmpty()) {
            return fallbackHtml(req);
        }

        try {
            Context ctx = new Context();
            if (req.getVariables() != null) {
                ctx.setVariables(req.getVariables());
            }
            return templateEngine.get().process(template, ctx);
        } catch (Exception e) {
            log.warn("No se encontro plantilla '{}', usando fallback. {}", template, e.getMessage());
            return fallbackHtml(req);
        }
    }

    private String resolverAsunto(EmailRequest req) {
        if (req.getSubject() != null && !req.getSubject().isBlank()) {
            return req.getSubject();
        }
        return asuntoPorDefecto(req.getTipo());
    }

    /**
     * Reemplaza los valores secretos dentro del HTML ya renderizado. Se hace
     * sobre el resultado y no sobre las variables para que la plantilla real
     * siga viendo el codigo o la clave.
     */
    private String enmascarar(String html, Map<String, Object> variables) {
        if (html == null || variables == null || variables.isEmpty()) {
            return html;
        }
        String resultado = html;
        for (Map.Entry<String, Object> entrada : variables.entrySet()) {
            if (!CLAVES_SECRETAS.contains(entrada.getKey().toLowerCase(Locale.ROOT))) {
                continue;
            }
            String valor = String.valueOf(entrada.getValue());
            if (valor.isBlank() || "null".equals(valor)) {
                continue;
            }
            // Thymeleaf escapa el HTML (un & se guarda como &amp;), asi que se
            // tapa la forma cruda y la escapada.
            String escapado = HtmlUtils.htmlEscape(valor);
            if (!escapado.equals(valor)) {
                resultado = resultado.replace(escapado, MASCARA);
            }
            resultado = resultado.replace(valor, MASCARA);
        }
        return resultado;
    }

    private String fallbackHtml(EmailRequest req) {
        StringBuilder sb = new StringBuilder("<html><body>");
        sb.append("<h2>Mercado Animales</h2>");
        if (req.getVariables() != null) {
            req.getVariables().forEach((k, v) ->
                    sb.append("<p><b>").append(k).append(":</b> ").append(v).append("</p>"));
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    private String asuntoPorDefecto(String tipo) {
        if (tipo == null) return "Notificacion Mercado Animales";
        return switch (tipo.toUpperCase(Locale.ROOT)) {
            case "VERIFICACION", "VERIFICACION_CODIGO" -> "Verifica tu cuenta - Mercado Animales";
            case "RECUPERACION" -> "Recupera tu contrasena - Mercado Animales";
            case "CREDENCIALES" -> "Tus credenciales de acceso - Mercado Animales";
            case "CUENTA_BLOQUEADA" -> "Tu cuenta fue bloqueada - Mercado Animales";
            case "CUENTA_REACTIVADA" -> "Tu cuenta fue reactivada - Mercado Animales";
            case "PRUEBA" -> "Correo de prueba - Mercado Animales";
            case "PERSONALIZADO" -> "Mensaje del Mercado de Ganado";
            case "COMPRA" -> "Confirmacion de compra - Mercado Animales";
            case "VENTA" -> "Confirmacion de venta - Mercado Animales";
            case "CANCELACION" -> "Cancelacion de compra - Mercado Animales";
            case "CONTACTO" -> "Nuevo mensaje - Mercado Animales";
            case "OFERTA" -> "Nueva oferta - Mercado Animales";
            case "RECOMENDACION", "RECOMENDACIONES" -> "Recomendaciones - Mercado Animales";
            default -> "Notificacion Mercado Animales";
        };
    }

    private String mensajeDe(Exception e) {
        Throwable causa = e;
        while (causa.getCause() != null && causa.getCause() != causa) {
            causa = causa.getCause();
        }
        String mensaje = causa.getMessage();
        return mensaje == null || mensaje.isBlank() ? causa.getClass().getSimpleName() : mensaje;
    }

    private String recortar(String texto, int maximo) {
        if (texto == null) return null;
        return texto.length() <= maximo ? texto : texto.substring(0, maximo);
    }
}
