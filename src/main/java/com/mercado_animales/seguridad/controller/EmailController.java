package com.mercado_animales.seguridad.controller;

import com.mercado_animales.notificacion.EmailEnviado;
import com.mercado_animales.notificacion.EstadoEmail;
import com.mercado_animales.seguridad.dto.EmailEnviadoResponse;
import com.mercado_animales.seguridad.dto.EmailPersonalizadoRequest;
import com.mercado_animales.seguridad.dto.EmailRequest;
import com.mercado_animales.seguridad.dto.EmailResponse;
import com.mercado_animales.seguridad.dto.PaginaEmails;
import com.mercado_animales.seguridad.exception.ApiException;
import com.mercado_animales.seguridad.repository.EmailEnviadoRepository;
import com.mercado_animales.seguridad.repository.UsuarioRepository;
import com.mercado_animales.seguridad.security.UsuarioAutenticado;
import com.mercado_animales.seguridad.service.EmailService;
import com.mercado_animales.seguridad.service.NotificacionService;
import com.mercado_animales.usuario.Usuario;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.persistence.criteria.Predicate;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@RestController
@RequestMapping("/api/emails")
@RequiredArgsConstructor
@Tag(name = "Correos", description = "Envio y bandeja de correos de la plataforma")
public class EmailController {

    private final EmailService emailService;
    private final NotificacionService notificacionService;
    private final EmailEnviadoRepository emailEnviadoRepository;
    private final UsuarioRepository usuarioRepository;

    @PostMapping
    @PreAuthorize("hasAnyRole('SERVICE', 'ADMIN')")
    @Operation(summary = "Envia un email (interno o ADMIN)")
    public ResponseEntity<EmailResponse> enviar(@Valid @RequestBody EmailRequest request) {
        emailService.enviar(request);
        return ResponseEntity.accepted().body(new EmailResponse(true, "Email encolado para envio"));
    }

    /**
     * Correo libre desde la bandeja: el ADMIN elige los usuarios y redacta
     * asunto y mensaje. Se manda uno por destinatario para no exponer las
     * direcciones del resto, y cada intento queda registrado en la bandeja.
     */
    @PostMapping("/personalizado")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Envia un correo personalizado a los usuarios elegidos")
    public ResponseEntity<EmailResponse> enviarPersonalizado(
            @Valid @RequestBody EmailPersonalizadoRequest request,
            Authentication authentication) {

        List<Usuario> usuarios = usuarioRepository.findByIdInWithRoles(request.getUsuarioIds());
        if (usuarios.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "No se encontraron los usuarios elegidos");
        }

        String remitente = remitente(authentication);
        String asunto = request.getAsunto().trim();
        String mensaje = request.getMensaje().trim();

        Set<String> destinos = new LinkedHashSet<>();
        int inactivos = 0;
        for (Usuario usuario : usuarios) {
            if (!Boolean.TRUE.equals(usuario.getActivo())
                    || usuario.getEmail() == null || usuario.getEmail().isBlank()) {
                inactivos++;
                continue;
            }
            // LinkedHashSet: si dos ids apuntan al mismo email, se manda una vez.
            if (!destinos.add(usuario.getEmail())) {
                continue;
            }
            notificacionService.enviarPersonalizado(
                    usuario.getEmail(), usuario.getNombre(), asunto, mensaje, remitente);
        }

        if (destinos.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "Ninguno de los usuarios elegidos puede recibir correos (cuentas inactivas o sin email)");
        }

        String resumen = "Correo encolado para " + destinos.size()
                + (destinos.size() == 1 ? " destinatario" : " destinatarios");
        if (inactivos > 0) {
            resumen += ". Se omitieron " + inactivos + " por estar inactivos";
        }
        return ResponseEntity.accepted().body(new EmailResponse(true, resumen));
    }

    private String remitente(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof UsuarioAutenticado usuario
                && usuario.getEmail() != null) {
            return usuarioRepository.findByEmail(usuario.getEmail())
                    .map(Usuario::getNombre)
                    .filter(nombre -> nombre != null && !nombre.isBlank())
                    .orElse("El equipo del Mercado de Ganado");
        }
        return "El equipo del Mercado de Ganado";
    }

    /**
     * Bandeja de enviados. Solo ADMIN: es informacion operativa, no de negocio,
     * y puede contener el contenido de los correos.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Lista los correos enviados con filtros y paginacion")
    public ResponseEntity<PaginaEmails> listar(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String tipo,
            @RequestParam(required = false) String estado,
            @RequestParam(required = false) String destinatario) {

        Specification<EmailEnviado> spec = (root, query, cb) -> {
            List<Predicate> filtros = new ArrayList<>();
            if (tipo != null && !tipo.isBlank()) {
                filtros.add(cb.equal(cb.upper(root.get("tipo")), tipo.toUpperCase(Locale.ROOT)));
            }
            if (estado != null && !estado.isBlank()) {
                filtros.add(cb.equal(root.get("estado"), parseEstado(estado)));
            }
            if (destinatario != null && !destinatario.isBlank()) {
                filtros.add(cb.like(cb.lower(root.get("destinatarios")),
                        "%" + destinatario.toLowerCase(Locale.ROOT) + "%"));
            }
            return filtros.isEmpty() ? cb.conjunction() : cb.and(filtros.toArray(new Predicate[0]));
        };

        int pagina = Math.max(page, 0);
        int tamano = Math.min(Math.max(size, 1), 100);
        Page<EmailEnviado> resultado = emailEnviadoRepository.findAll(spec,
                PageRequest.of(pagina, tamano, Sort.by(Sort.Direction.DESC, "creadoEn")));

        List<EmailEnviadoResponse> content = resultado.getContent().stream()
                .map(this::aResumen)
                .toList();

        return ResponseEntity.ok(new PaginaEmails(content, resultado.getTotalElements(),
                resultado.getTotalPages(), resultado.getNumber(), resultado.getSize()));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Detalle de un correo, con el HTML que se envio")
    public ResponseEntity<EmailEnviadoResponse> detalle(@PathVariable Integer id) {
        EmailEnviado correo = emailEnviadoRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Correo no encontrado"));

        EmailEnviadoResponse respuesta = aResumen(correo);
        respuesta.setHtml(correo.getHtml());
        return ResponseEntity.ok(respuesta);
    }

    private EmailEnviadoResponse aResumen(EmailEnviado correo) {
        EmailEnviadoResponse r = new EmailEnviadoResponse();
        r.setId(correo.getId());
        r.setDestinatarios(correo.getDestinatarios());
        r.setAsunto(correo.getAsunto());
        r.setTipo(correo.getTipo());
        r.setEstado(correo.getEstado() == null ? null : correo.getEstado().name());
        r.setError(correo.getError());
        r.setCreadoEn(correo.getCreadoEn());
        r.setEnviadoEn(correo.getEnviadoEn());
        return r;
    }

    private EstadoEmail parseEstado(String estado) {
        try {
            return EstadoEmail.valueOf(estado.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "Estado invalido. Usa PENDIENTE, ENVIADO o FALLIDO");
        }
    }
}
