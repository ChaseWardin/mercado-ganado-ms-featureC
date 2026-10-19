package com.mercado_animales.seguridad.config;

import com.mercado_animales.seguridad.repository.RolRepository;
import com.mercado_animales.seguridad.repository.UsuarioRepository;
import com.mercado_animales.usuario.Rol;
import com.mercado_animales.usuario.Usuario;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.util.Locale;

/**
 * Crea el usuario ADMIN, pero solo si el seed esta habilitado de forma explicita
 * ({@code app.seed-admin.enabled=true}) y se recibieron email y password por
 * configuracion/entorno.
 *
 * <p>Esta apagado por defecto a proposito: un seed automatico con credenciales
 * conocidas no debe existir en un servicio de seguridad. Ademas, como la
 * creacion se decide por email, dejarlo siempre encendido permitiria que, al
 * cambiar las variables de entorno, se cree un administrador adicional.
 *
 * <p>Se ejecuta como ApplicationRunner (no en @PostConstruct) para garantizar
 * que Liquibase ya creo las tablas y sembro los roles antes de tocar la BD.
 * Si el admin ya existe no hace nada.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements ApplicationRunner {

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.seed-admin.enabled:false}")
    private boolean seedEnabled;

    @Value("${app.seed-admin.email:}")
    private String adminEmail;

    @Value("${app.seed-admin.password:}")
    private String adminPassword;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!seedEnabled) {
            log.info("Seed admin deshabilitado (app.seed-admin.enabled=false)");
            return;
        }

        if (!StringUtils.hasText(adminEmail) || !StringUtils.hasText(adminPassword)) {
            log.warn("Seed admin habilitado pero sin email/password configurados; se omite");
            return;
        }

        String email = normalizarEmail(adminEmail);
        if (usuarioRepository.existsByEmail(email)) {
            log.info("Seed admin: ya existe {}", email);
            return;
        }

        Rol admin = rolRepository.findByName("ADMIN").orElse(null);
        if (admin == null) {
            log.warn("Seed admin omitido: el rol ADMIN no existe (¿corrio Liquibase?)");
            return;
        }

        Usuario usuario = new Usuario();
        usuario.setNombre("Admin");
        usuario.setEmail(email);
        usuario.setPasswordHash(passwordEncoder.encode(adminPassword));
        usuario.setFechaRegistro(LocalDate.now());
        usuario.setActivo(true);
        usuario.getRoles().add(admin);
        usuarioRepository.save(usuario);

        // Nunca se registra el password.
        log.info("Seed admin creado: {}", email);
    }

    private String normalizarEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
