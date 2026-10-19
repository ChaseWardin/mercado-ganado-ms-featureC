package com.mercado_animales.seguridad.service;

import com.mercado_animales.seguridad.dto.EmailRequest;
import jakarta.annotation.PostConstruct;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    @Autowired
    private JavaMailSender mailSender;

    @Autowired(required = false)
    private TemplateEngine templateEngine;

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
        try {
            String html = req.getHtml();
            if (html == null || html.isBlank()) {
                String template = (req.getTipo() == null ? "generic" : req.getTipo().toLowerCase());
                if (templateEngine != null) {
                    try {
                        Context ctx = new Context();
                        if (req.getVariables() != null) {
                            ctx.setVariables(req.getVariables());
                        }
                        html = templateEngine.process(template, ctx);
                    } catch (Exception e) {
                        log.warn("No se encontro plantilla '{}', usando fallback. {}", template, e.getMessage());
                        html = fallbackHtml(req);
                    }
                } else {
                    html = fallbackHtml(req);
                }
            }

            String subject = req.getSubject();
            if (subject == null || subject.isBlank()) {
                subject = asuntoPorDefecto(req.getTipo());
            }

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            helper.setFrom(from);
            helper.setTo(req.getTo().toArray(new String[0]));
            helper.setSubject(subject);
            helper.setText(html, true);
            mailSender.send(message);
            log.info("Email enviado a {} (tipo={})", req.getTo(), req.getTipo());
        } catch (Exception e) {
            log.error("Fallo al enviar email a {}: {}", req.getTo(), e.getMessage(), e);
        }
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
        return switch (tipo.toUpperCase()) {
            case "VERIFICACION", "VERIFICACION_CODIGO" -> "Verifica tu cuenta - Mercado Animales";
            case "COMPRA" -> "Confirmacion de compra - Mercado Animales";
            case "VENTA" -> "Confirmacion de venta - Mercado Animales";
            case "CANCELACION" -> "Cancelacion de compra - Mercado Animales";
            case "CONTACTO" -> "Nuevo mensaje - Mercado Animales";
            case "OFERTA" -> "Nueva oferta - Mercado Animales";
            case "RECOMENDACION", "RECOMENDACIONES" -> "Recomendaciones - Mercado Animales";
            default -> "Notificacion Mercado Animales";
        };
    }
}
