package com.mercado_animales.seguridad.config;

import com.mercado_animales.seguridad.repository.RolRepository;
import com.mercado_animales.seguridad.repository.UsuarioRepository;
import com.mercado_animales.usuario.Rol;
import com.mercado_animales.usuario.Usuario;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;

/**
 * Crea el usuario ADMIN la primera vez.
 *
 * <p>Se ejecuta como ApplicationRunner (no en @PostConstruct) para garantizar
 * que Liquibase ya creo las tablas y sembro los roles antes de tocar la BD.
 * Si el admin ya existe no hace nada.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements ApplicationRunner {

    private static final String ADMIN_EMAIL = "admin@mercado.com";
    private static final String ADMIN_PASSWORD = "admin123";

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (usuarioRepository.existsByEmail(ADMIN_EMAIL)) {
            log.info("Seed admin: ya existe {}", ADMIN_EMAIL);
            return;
        }

        Rol admin = rolRepository.findByName("ADMIN").orElse(null);
        if (admin == null) {
            log.warn("Seed admin omitido: el rol ADMIN no existe (¿corrio Liquibase?)");
            return;
        }

        Usuario usuario = new Usuario();
        usuario.setNombre("Admin");
        usuario.setEmail(ADMIN_EMAIL);
        usuario.setPasswordHash(passwordEncoder.encode(ADMIN_PASSWORD));
        usuario.setFechaRegistro(LocalDate.now());
        usuario.setActivo(true);
        usuario.getRoles().add(admin);
        usuarioRepository.save(usuario);

        log.info("Seed admin creado: {} / {}", ADMIN_EMAIL, ADMIN_PASSWORD);
    }
}
