package com.mercado_animales.seguridad.service;

import com.mercado_animales.seguridad.dto.EmailRequest;
import com.mercado_animales.seguridad.dto.PerfilUpdateRequest;
import com.mercado_animales.seguridad.dto.UsuarioCreateRequest;
import com.mercado_animales.seguridad.dto.UsuarioUpdateRequest;
import com.mercado_animales.seguridad.dto.VerificarRegistroRequest;
import com.mercado_animales.seguridad.exception.ApiException;
import com.mercado_animales.seguridad.repository.RolRepository;
import com.mercado_animales.seguridad.repository.UsuarioRepository;
import com.mercado_animales.seguridad.repository.UsuarioRolRepository;
import com.mercado_animales.seguridad.security.JwtService;
import com.mercado_animales.usuario.Rol;
import com.mercado_animales.usuario.Usuario;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Unico servicio que emite tokens JWT y que escribe en la tabla usuarios.
 *
 * <p>El registro es DIFERIDO: {@link #iniciarRegistro} no inserta nada en
 * {@code usuarios}; guarda el alta en un mapa de pendientes (en memoria) y
 * envia un codigo de 6 digitos. La fila en {@code usuarios} recien se crea en
 * {@link #confirmarRegistro}, despues de validar el codigo.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private static final String ROL_VENDEDOR = "VENDEDOR";
    private static final String ROL_COMPRADOR = "COMPRADOR";

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final UsuarioRolRepository usuarioRolRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final EmailService emailService;

    @Value("${app.jwt.expiration-ms:86400000}")
    private long expirationMs;

    /**
     * Registros aun NO confirmados. No tocan la base de datos a proposito: si
     * el servicio se reinicia dentro de los 5 minutos, el pendiente se pierde y
     * el usuario debe rehacer el registro. Es el precio de no ensuciar la tabla
     * usuarios con altas sin verificar.
     */
    private final ConcurrentHashMap<String, RegistroPendiente> pendientes = new ConcurrentHashMap<>();

    public record TokenResponse(String token, String tipo, long expiraEn, Integer usuarioId, String email,
                                String nombre, List<String> roles) {}

    // ------------------------------------------------------------------
    // Registro diferido
    // ------------------------------------------------------------------

    public String iniciarRegistroVendedor(String email, String nombre, String password, String telefono, String ruc) {
        return iniciarRegistro(email, nombre, password, telefono, ruc, ROL_VENDEDOR);
    }

    public String iniciarRegistroComprador(String email, String nombre, String password, String telefono, String ruc) {
        return iniciarRegistro(email, nombre, password, telefono, ruc, ROL_COMPRADOR);
    }

    @Transactional(readOnly = true)
    public String iniciarRegistro(String email, String nombre, String password, String telefono, String ruc, String rol) {
        String normalized = normalizarEmail(email);

        if (usuarioRepository.existsByEmail(normalized)) {
            throw new ApiException(HttpStatus.CONFLICT, "Ya existe un usuario con el email " + normalized);
        }
        // El rol debe existir antes de aceptar el registro (si no, fallaria al confirmar).
        rolRepository.findByName(rol)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "El rol " + rol + " no existe"));

        removeIfExpired(normalized);
        if (pendientes.containsKey(normalized)) {
            throw new ApiException(HttpStatus.CONFLICT, "Ya hay un registro pendiente para " + normalized
                    + "; revisa tu email o solicita un nuevo codigo");
        }

        String codigo = generarCodigo();
        pendientes.put(normalized, new RegistroPendiente(
                nombre.trim(),
                normalized,
                passwordEncoder.encode(password),
                telefono,
                ruc,
                rol,
                passwordEncoder.encode(codigo),
                LocalDateTime.now().plusMinutes(5),
                0));

        EmailRequest emailReq = new EmailRequest();
        emailReq.setTo(List.of(normalized));
        emailReq.setTipo("VERIFICACION_CODIGO");
        emailReq.setVariables(Map.of("nombre", nombre.trim(), "codigo", codigo));
        emailService.enviar(emailReq);

        log.info("Registro pendiente creado para {} (rol={}); codigo enviado", normalized, rol);
        return "Se envio un codigo de verificacion al correo " + normalized;
    }

    /**
     * Valida el codigo y, SOLO ENTONCES, inserta al usuario en la base de datos.
     */
    @Transactional
    public TokenResponse confirmarRegistro(VerificarRegistroRequest request) {
        String email = normalizarEmail(request.getEmail());
        RegistroPendiente pendiente = pendientes.get(email);
        if (pendiente == null || pendiente.expiraEn.isBefore(LocalDateTime.now())) {
            pendientes.remove(email);
            throw new ApiException(HttpStatus.BAD_REQUEST, "No hay registro pendiente o el codigo expiro");
        }
        if (pendiente.intentos >= 5) {
            pendientes.remove(email);
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "Demasiados intentos. Solicita un nuevo codigo");
        }
        pendiente.intentos++;
        if (!passwordEncoder.matches(request.getCodigo(), pendiente.codigoHash)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Codigo de verificacion invalido");
        }

        Rol rol = rolRepository.findByName(pendiente.nombreRol)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "El rol no existe"));

        Usuario usuario = new Usuario();
        usuario.setNombre(pendiente.nombre);
        usuario.setEmail(email);
        usuario.setPasswordHash(pendiente.passwordHash);
        usuario.setTelefono(pendiente.telefono);
        usuario.setRuc(pendiente.ruc);
        usuario.setFechaRegistro(LocalDate.now());
        usuario.setActivo(true);
        usuario.getRoles().add(rol);

        Usuario guardado = usuarioRepository.save(usuario);
        pendientes.remove(email);
        log.info("Usuario verificado y creado: id={}, email={}, rol={}",
                guardado.getId(), guardado.getEmail(), pendiente.nombreRol);
        return buildToken(guardado);
    }

    // ------------------------------------------------------------------
    // Login
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public TokenResponse login(String email, String password) {
        // findByEmailWithRoles y no findByEmail: buildToken necesita los roles
        // ya inicializados (son LAZY).
        Usuario usuario = usuarioRepository.findByEmailWithRoles(normalizarEmail(email))
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas"));

        if (!Boolean.TRUE.equals(usuario.getActivo())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas");
        }
        if (!passwordEncoder.matches(password, usuario.getPasswordHash())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas");
        }
        if (usuario.getRoles().isEmpty()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "El usuario no tiene ningun rol asignado");
        }

        log.info("Login OK: id={}, email={}", usuario.getId(), usuario.getEmail());
        return buildToken(usuario);
    }

    // ------------------------------------------------------------------
    // Gestion de usuarios (ADMIN)
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public PaginaUsuarios listarUsuarios(int page, int size, String nombre, String email, String rol, Boolean activo) {
        Specification<Usuario> spec = (root, query, cb) -> {
            List<Predicate> filtros = new ArrayList<>();
            if (nombre != null && !nombre.isBlank()) {
                filtros.add(cb.like(cb.lower(root.get("nombre")), "%" + nombre.toLowerCase(Locale.ROOT) + "%"));
            }
            if (email != null && !email.isBlank()) {
                filtros.add(cb.like(cb.lower(root.get("email")), "%" + email.toLowerCase(Locale.ROOT) + "%"));
            }
            if (activo != null) {
                filtros.add(cb.equal(root.get("activo"), activo));
            }
            if (rol != null && !rol.isBlank()) {
                Join<Usuario, Rol> roles = root.join("roles");
                filtros.add(cb.equal(cb.upper(roles.get("name")), rol.toUpperCase(Locale.ROOT)));
                query.distinct(true);
            }
            return filtros.isEmpty() ? cb.conjunction() : cb.and(filtros.toArray(new Predicate[0]));
        };

        Page<Usuario> resultado = usuarioRepository.findAll(spec, PageRequest.of(page, size));
        List<UsuarioResponse> content = resultado.getContent().stream().map(UsuarioResponse::from).toList();
        return new PaginaUsuarios(content, resultado.getTotalElements(),
                resultado.getTotalPages(), resultado.getNumber(), resultado.getSize());
    }

    /**
     * Cacheado por id: dominio {@code usuarios}. Se invalida en cada escritura
     * sobre el usuario (actualizar, desactivar, cambiar roles).
     */
    @Cacheable(cacheNames = "usuarios", key = "#id")
    @Transactional(readOnly = true)
    public UsuarioResponse getById(Integer id) {
        return usuarioRepository.findById(id)
                .map(UsuarioResponse::from)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
    }

    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#id"),
            @CacheEvict(cacheNames = "usuarios-por-email", key = "#result.email")
    })
    @Transactional
    public UsuarioResponse desactivar(Integer id) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        usuario.setActivo(false);
        usuarioRepository.save(usuario);
        log.info("Usuario desactivado: id={}, email={}", usuario.getId(), usuario.getEmail());
        return UsuarioResponse.from(usuario);
    }

    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#id"),
            @CacheEvict(cacheNames = "usuarios-por-email", key = "#result.email")
    })
    @Transactional
    public UsuarioResponse asignarRol(Integer id, String rol) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        Rol rolEntidad = rolRepository.findByName(rol.toUpperCase(Locale.ROOT))
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "El rol " + rol + " no existe"));

        usuarioRolRepository.reactivar(usuario.getId(), rolEntidad.getId());
        log.info("Rol {} asignado al usuario id={}", rolEntidad.getName(), usuario.getId());

        return UsuarioResponse.from(usuarioRepository.findByEmailWithRoles(usuario.getEmail())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado")));
    }

    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#id"),
            @CacheEvict(cacheNames = "usuarios-por-email", key = "#result.email")
    })
    @Transactional
    public UsuarioResponse quitarRol(Integer id, String rol) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        Rol rolEntidad = rolRepository.findByName(rol.toUpperCase(Locale.ROOT))
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "El rol " + rol + " no existe"));

        usuarioRolRepository.desactivar(usuario.getId(), rolEntidad.getId());
        log.info("Rol {} quitado al usuario id={}", rolEntidad.getName(), usuario.getId());

        return UsuarioResponse.from(usuarioRepository.findByEmailWithRoles(usuario.getEmail())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado")));
    }

    // ------------------------------------------------------------------
    // Alta y edicion (ADMIN) y edicion del propio perfil
    // ------------------------------------------------------------------

    @Transactional
    public UsuarioResponse crearUsuario(UsuarioCreateRequest request) {
        String email = normalizarEmail(request.getEmail());
        if (usuarioRepository.existsByEmail(email)) {
            throw new ApiException(HttpStatus.CONFLICT, "Ya existe un usuario con el email " + email);
        }

        Usuario usuario = new Usuario();
        usuario.setNombre(request.getNombre().trim());
        usuario.setEmail(email);
        usuario.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        usuario.setTelefono(request.getTelefono());
        usuario.setRuc(request.getRuc());
        usuario.setFechaRegistro(LocalDate.now());
        usuario.setActivo(request.getActivo() == null || request.getActivo());

        List<String> nombresRoles = (request.getRoles() == null || request.getRoles().isEmpty())
                ? List.of(ROL_COMPRADOR)
                : request.getRoles();
        for (String nombreRol : nombresRoles) {
            Rol rol = rolRepository.findByName(nombreRol.toUpperCase(Locale.ROOT))
                    .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST,
                            "El rol " + nombreRol + " no existe"));
            usuario.getRoles().add(rol);
        }

        Usuario guardado = usuarioRepository.save(usuario);
        log.info("Usuario creado por admin: id={}, email={}, roles={}",
                guardado.getId(), guardado.getEmail(), nombresRoles);
        return UsuarioResponse.from(guardado);
    }

    /**
     * El email puede cambiar, asi que el cache por email se limpia completo:
     * no alcanza con invalidar la clave del email nuevo.
     */
    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#id"),
            @CacheEvict(cacheNames = "usuarios-por-email", allEntries = true)
    })
    @Transactional
    public UsuarioResponse actualizarUsuario(Integer id, UsuarioUpdateRequest request) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));

        String email = normalizarEmail(request.getEmail());
        usuarioRepository.findByEmail(email)
                .filter(otro -> !otro.getId().equals(id))
                .ifPresent(otro -> {
                    throw new ApiException(HttpStatus.CONFLICT, "Ya existe un usuario con el email " + email);
                });

        usuario.setNombre(request.getNombre().trim());
        usuario.setEmail(email);
        usuario.setTelefono(request.getTelefono());
        usuario.setRuc(request.getRuc());
        if (request.getActivo() != null) {
            usuario.setActivo(request.getActivo());
        }
        usuarioRepository.save(usuario);

        log.info("Usuario actualizado por admin: id={}, email={}", usuario.getId(), usuario.getEmail());
        return UsuarioResponse.from(usuarioRepository.findByEmailWithRoles(email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado")));
    }

    /**
     * Edicion del propio perfil. Solo nombre, telefono y ruc: el email es el
     * identificador de login y cambiarlo exigiria reverificar la cuenta.
     */
    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#id"),
            @CacheEvict(cacheNames = "usuarios-por-email", key = "#result.email")
    })
    @Transactional
    public UsuarioResponse actualizarPerfil(Integer id, PerfilUpdateRequest request) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));

        usuario.setNombre(request.getNombre().trim());
        usuario.setTelefono(request.getTelefono());
        usuario.setRuc(request.getRuc());
        usuarioRepository.save(usuario);

        log.info("Perfil actualizado: id={}, email={}", usuario.getId(), usuario.getEmail());
        return UsuarioResponse.from(usuarioRepository.findByEmailWithRoles(usuario.getEmail())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado")));
    }

    /**
     * Cacheado por email normalizado (el mismo que usa el login).
     */
    @Cacheable(cacheNames = "usuarios-por-email", key = "#email.toLowerCase()")
    @Transactional(readOnly = true)
    public UsuarioResponse getByEmail(String email) {
        return usuarioRepository.findByEmailWithRoles(normalizarEmail(email))
                .map(UsuarioResponse::from)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
    }

    // ------------------------------------------------------------------
    // Activacion de roles (devuelve un token nuevo, porque los roles van en el JWT)
    // ------------------------------------------------------------------

    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#usuarioId"),
            @CacheEvict(cacheNames = "usuarios-por-email", key = "#result.email")
    })
    public TokenResponse activarRolVendedor(Integer usuarioId) {
        return activarRol(usuarioId, ROL_VENDEDOR);
    }

    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#usuarioId"),
            @CacheEvict(cacheNames = "usuarios-por-email", key = "#result.email")
    })
    public TokenResponse activarRolComprador(Integer usuarioId) {
        return activarRol(usuarioId, ROL_COMPRADOR);
    }

    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#usuarioId"),
            @CacheEvict(cacheNames = "usuarios-por-email", key = "#result.email")
    })
    @Transactional
    public TokenResponse activarRol(Integer usuarioId, String nombreRol) {
        Usuario usuario = usuarioRepository.findById(usuarioId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        if (!Boolean.TRUE.equals(usuario.getActivo())) {
            throw new ApiException(HttpStatus.FORBIDDEN, "El usuario esta inactivo");
        }
        Rol rol = rolRepository.findByName(nombreRol)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "El rol " + nombreRol + " no existe"));

        String email = usuario.getEmail();
        usuarioRolRepository.reactivar(usuarioId, rol.getId());
        log.info("Rol {} agregado al usuario id={}", nombreRol, usuarioId);

        return buildToken(usuarioRepository.findByEmailWithRoles(email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado")));
    }

    // ------------------------------------------------------------------
    // Apoyo
    // ------------------------------------------------------------------

    private TokenResponse buildToken(Usuario usuario) {
        List<String> roles = usuario.getRoles().stream()
                .map(Rol::getName)
                .sorted()
                .toList();
        String token = jwtService.generarToken(usuario.getEmail(), usuario.getId(), roles);
        return new TokenResponse(token, "Bearer", expirationMs, usuario.getId(),
                usuario.getEmail(), usuario.getNombre(), roles);
    }

    private void removeIfExpired(String email) {
        RegistroPendiente p = pendientes.get(email);
        if (p != null && p.expiraEn.isBefore(LocalDateTime.now())) {
            pendientes.remove(email);
        }
    }

    private String normalizarEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String generarCodigo() {
        return String.format("%06d", new java.security.SecureRandom().nextInt(1_000_000));
    }

    private static class RegistroPendiente {
        final String nombre;
        final String email;
        final String passwordHash;
        final String telefono;
        final String ruc;
        final String nombreRol;
        final String codigoHash;
        final LocalDateTime expiraEn;
        int intentos;

        RegistroPendiente(String nombre, String email, String passwordHash, String telefono, String ruc,
                          String nombreRol, String codigoHash, LocalDateTime expiraEn, int intentos) {
            this.nombre = nombre;
            this.email = email;
            this.passwordHash = passwordHash;
            this.telefono = telefono;
            this.ruc = ruc;
            this.nombreRol = nombreRol;
            this.codigoHash = codigoHash;
            this.expiraEn = expiraEn;
            this.intentos = intentos;
        }
    }

    // ------------------------------------------------------------------
    // DTOs de salida
    // ------------------------------------------------------------------

    public static class UsuarioResponse {
        public Integer id;
        public String nombre;
        public String email;
        public String telefono;
        public String ruc;
        public boolean activo;
        public List<String> roles = new ArrayList<>();

        public static UsuarioResponse from(Usuario u) {
            UsuarioResponse r = new UsuarioResponse();
            r.id = u.getId();
            r.nombre = u.getNombre();
            r.email = u.getEmail();
            r.telefono = u.getTelefono();
            r.ruc = u.getRuc();
            r.activo = Boolean.TRUE.equals(u.getActivo());
            r.roles.addAll(u.getRoles().stream().map(Rol::getName).sorted().toList());
            return r;
        }
    }

    public record PaginaUsuarios(List<UsuarioResponse> content, long totalElements,
                                 int totalPages, int number, int size) {}
}
