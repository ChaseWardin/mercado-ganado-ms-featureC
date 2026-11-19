package com.mercado_animales.seguridad.service;

import com.mercado_animales.seguridad.dto.CambiarPasswordRequest;
import com.mercado_animales.seguridad.dto.ModoFacturacionRequest;
import com.mercado_animales.seguridad.dto.PerfilUpdateRequest;
import com.mercado_animales.seguridad.dto.ReiniciarPasswordRequest;
import com.mercado_animales.seguridad.dto.UsuarioCreateRequest;
import com.mercado_animales.seguridad.dto.UsuarioUpdateRequest;
import com.mercado_animales.seguridad.dto.VerificarRegistroRequest;
import com.mercado_animales.seguridad.exception.ApiException;
import com.mercado_animales.seguridad.repository.RolRepository;
import com.mercado_animales.seguridad.repository.UsuarioRepository;
import com.mercado_animales.seguridad.repository.UsuarioRolRepository;
import com.mercado_animales.seguridad.security.JwtService;
import com.mercado_animales.usuario.ModoFacturacion;
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
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

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
    private static final String ROL_ADMIN = "ADMIN";
    private static final String ROL_FUNCIONARIO = "FUNCIONARIO";

    /** Roles que un ADMIN puede alternar desde la tabla de usuarios. */
    private static final Set<String> ROLES_CONVERTIBLES = Set.of(ROL_COMPRADOR, ROL_VENDEDOR);

    /** Roles especiales: se asignan al crear la cuenta y no se convierten. */
    private static final Set<String> ROLES_ESPECIALES = Set.of(ROL_ADMIN, ROL_FUNCIONARIO);

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final UsuarioRolRepository usuarioRolRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final NotificacionService notificacionService;

    @Value("${app.jwt.expiration-ms:86400000}")
    private long expirationMs;

    /**
     * Registros aun NO confirmados. No tocan la base de datos a proposito: si
     * el servicio se reinicia dentro de los 5 minutos, el pendiente se pierde y
     * el usuario debe rehacer el registro. Es el precio de no ensuciar la tabla
     * usuarios con altas sin verificar.
     */
    private final ConcurrentHashMap<String, RegistroPendiente> pendientes = new ConcurrentHashMap<>();

    /**
     * Recuperaciones de contrasena en curso. Igual que los registros
     * pendientes, viven en memoria: si el servicio se reinicia, el codigo se
     * pierde y hay que pedir otro. Se guarda el hash, nunca el codigo en claro.
     */
    private final ConcurrentHashMap<String, RecuperacionPendiente> recuperaciones = new ConcurrentHashMap<>();

    /** Espera minima entre dos codigos para el mismo correo. */
    private static final long ESPERA_REENVIO_SEGUNDOS = 60;

    public record TokenResponse(String token, String tipo, long expiraEn, Integer usuarioId, String email,
                                String nombre, List<String> roles, boolean debeCambiarPassword,
                                ModoFacturacion modoFacturacion) {}

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

        // Un segundo intento de registro con el mismo correo ya no responde
        // 409: se toma como un reenvio del codigo. La espera de 60 segundos
        // evita que el boton "Reenviar" se convierta en una metralleta de
        // correos y que el codigo cambie antes de que llegue el primero.
        RegistroPendiente previo = pendientes.get(normalized);
        if (previo != null
                && previo.ultimoEnvio.plusSeconds(ESPERA_REENVIO_SEGUNDOS).isAfter(LocalDateTime.now())) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS,
                    "Ya enviamos un codigo hace menos de un minuto. Espera para pedir otro.");
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
                0,
                LocalDateTime.now()));

        notificacionService.enviarVerificacion(normalized, nombre.trim(), codigo);

        log.info("Registro pendiente creado o renovado para {} (rol={}); codigo enviado", normalized, rol);
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
    // Recuperacion de contrasena (sin sesion)
    // ------------------------------------------------------------------

    /**
     * Genera un codigo de recuperacion y lo manda por correo.
     *
     * <p>La respuesta es siempre la misma exista o no la cuenta: si dijera
     * "ese correo no esta registrado", cualquiera podria averiguar quien tiene
     * cuenta en el mercado. Por la misma razon, cuando el pedido cae dentro de
     * la espera de 60 segundos se ignora en silencio.
     */
    public String solicitarRecuperacion(String email) {
        String normalized = normalizarEmail(email);
        String generico = "Si el correo esta registrado, enviamos un codigo de recuperacion.";

        usuarioRepository.findByEmail(normalized)
                .filter(usuario -> Boolean.TRUE.equals(usuario.getActivo()))
                .ifPresent(usuario -> {
                    LocalDateTime ahora = LocalDateTime.now();
                    RecuperacionPendiente previa = recuperaciones.get(normalized);
                    if (previa != null
                            && previa.ultimoEnvio.plusSeconds(ESPERA_REENVIO_SEGUNDOS).isAfter(ahora)) {
                        return;
                    }

                    String codigo = generarCodigo();
                    recuperaciones.put(normalized, new RecuperacionPendiente(
                            passwordEncoder.encode(codigo),
                            ahora.plusMinutes(15),
                            0,
                            ahora));

                    notificacionService.enviarRecuperacion(normalized, usuario.getNombre(), codigo);
                    log.info("Codigo de recuperacion enviado a {}", normalized);
                });

        return generico;
    }

    /**
     * Valida el codigo de recuperacion y reemplaza la contrasena.
     *
     * <p>El codigo tiene 15 minutos y 5 intentos. Se borra al usarlo, asi que
     * un enlace o codigo filtrado no sirve dos veces.
     */
    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", allEntries = true),
            @CacheEvict(cacheNames = "usuarios-por-email", allEntries = true)
    })
    @Transactional
    public String restablecerPassword(String email, String codigo, String passwordNueva) {
        String normalized = normalizarEmail(email);
        RecuperacionPendiente pendiente = recuperaciones.get(normalized);

        if (pendiente == null || pendiente.expiraEn.isBefore(LocalDateTime.now())) {
            recuperaciones.remove(normalized);
            throw new ApiException(HttpStatus.BAD_REQUEST, "El codigo es invalido o expiro. Solicita uno nuevo");
        }
        if (pendiente.intentos >= 5) {
            recuperaciones.remove(normalized);
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS,
                    "Demasiados intentos. Solicita un nuevo codigo");
        }

        pendiente.intentos++;
        if (!passwordEncoder.matches(codigo, pendiente.codigoHash)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "El codigo es invalido o expiro. Solicita uno nuevo");
        }

        Usuario usuario = usuarioRepository.findByEmail(normalized)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST,
                        "El codigo es invalido o expiro. Solicita uno nuevo"));

        usuario.setPasswordHash(passwordEncoder.encode(passwordNueva));
        // La clave la eligio el propio usuario: ya no es temporal.
        usuario.setDebeCambiarPassword(false);
        usuarioRepository.save(usuario);
        recuperaciones.remove(normalized);

        log.info("Contrasena restablecida por recuperacion: email={}", normalized);
        return "Contrasena actualizada. Ya puedes iniciar sesion.";
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

        // Primero la contrasena y despues el estado: el motivo de la baja solo
        // se le revela a quien demuestra conocer la cuenta. Si el password esta
        // mal, la respuesta sigue siendo el generico "Credenciales invalidas".
        if (!passwordEncoder.matches(password, usuario.getPasswordHash())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas");
        }
        if (!Boolean.TRUE.equals(usuario.getActivo())) {
            throw new ApiException(HttpStatus.FORBIDDEN, mensajeCuentaDesactivada(usuario));
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

        // UsuarioResponse incluye los roles y esa coleccion es LAZY: mapear
        // cada fila disparaba un SELECT por usuario (N+1). Ahora se traen los
        // roles de toda la pagina con una sola consulta, conservando el orden.
        List<Integer> ids = resultado.getContent().stream().map(Usuario::getId).toList();
        Map<Integer, Usuario> conRoles = ids.isEmpty() ? Map.of()
                : usuarioRepository.findByIdInWithRoles(ids).stream()
                        .collect(Collectors.toMap(Usuario::getId, usuario -> usuario));
        List<UsuarioResponse> content = ids.stream()
                .map(conRoles::get)
                .filter(Objects::nonNull)
                .map(UsuarioResponse::from)
                .toList();

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
        return usuarioRepository.findByIdWithRoles(id)
                .map(UsuarioResponse::from)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
    }

    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#id"),
            @CacheEvict(cacheNames = "usuarios-por-email", key = "#result.email")
    })
    @Transactional
    public UsuarioResponse desactivar(Integer id, String motivo) {
        // Se valida tambien aca y no solo en el DTO: el servicio es la ultima
        // barrera y cualquier otro llamador debe respetar que la baja explique
        // el motivo.
        if (motivo == null || motivo.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "El motivo de la desactivacion es obligatorio");
        }

        Usuario usuario = usuarioRepository.findByIdWithRoles(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        usuario.setActivo(false);
        usuario.setMotivoDesactivacion(motivo.trim());
        usuarioRepository.save(usuario);
        log.info("Usuario desactivado: id={}, email={}, motivo={}",
                usuario.getId(), usuario.getEmail(), motivo.trim());

        notificacionService.enviarCuentaBloqueada(usuario.getEmail(), usuario.getNombre(),
                usuario.getMotivoDesactivacion());

        return UsuarioResponse.from(usuario);
    }

    /**
     * Solo se permite convertir entre COMPRADOR y VENDEDOR. Los roles ADMIN y
     * FUNCIONARIO son especiales: se asignan al crear la cuenta y no se tocan
     * desde la tabla de usuarios.
     */
    private void validarConversionDeRol(Usuario usuario, Rol rol) {
        if (!ROLES_CONVERTIBLES.contains(rol.getName())) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "Solo se puede asignar o quitar el rol COMPRADOR o VENDEDOR");
        }
        boolean especial = usuario.getRoles().stream()
                .map(Rol::getName)
                .anyMatch(ROLES_ESPECIALES::contains);
        if (especial) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "Los usuarios ADMIN o FUNCIONARIO no se convierten entre COMPRADOR y VENDEDOR");
        }
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
        validarConversionDeRol(usuario, rolEntidad);

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
        validarConversionDeRol(usuario, rolEntidad);

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
        // La contrasena la eligio el ADMIN: es temporal y debe cambiarse al
        // entrar, aunque nada impide que el ADMIN cree cuentas con el flag
        // apagado en el futuro si aparece un caso que lo justifique.
        usuario.setDebeCambiarPassword(true);

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

        // La clave la definio el ADMIN y es temporal: viaja por correo junto con
        // la aclaracion de que debe cambiarla al ingresar.
        notificacionService.enviarCredenciales(guardado.getEmail(), guardado.getNombre(),
                request.getPassword());

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

        boolean estabaActivo = Boolean.TRUE.equals(usuario.getActivo());
        boolean reactivado = false;

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
            // Dar de baja exige motivo y ese es el camino del DELETE; por aca
            // solo se permite reactivar. Al reactivar se limpia el motivo para
            // que no quede pegado a una cuenta que ya volvio a estar activa.
            if (!request.getActivo() && Boolean.TRUE.equals(usuario.getActivo())) {
                throw new ApiException(HttpStatus.BAD_REQUEST,
                        "Para desactivar la cuenta usa DELETE /api/usuarios/" + id
                                + " indicando el motivo");
            }
            usuario.setActivo(request.getActivo());
            if (request.getActivo()) {
                usuario.setMotivoDesactivacion(null);
                reactivado = !estabaActivo;
            }
        }
        usuarioRepository.save(usuario);

        log.info("Usuario actualizado por admin: id={}, email={}", usuario.getId(), usuario.getEmail());

        if (reactivado) {
            notificacionService.enviarCuentaReactivada(usuario.getEmail(), usuario.getNombre());
        }

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
     * Cambio de contrasena del propio usuario. Es la pantalla a la que se
     * redirige a las cuentas creadas por un ADMIN, que arrancan con una
     * contrasena temporal. Se exige la actual para que un token robado no
     * alcance para quedarse con la cuenta.
     */
    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#id"),
            @CacheEvict(cacheNames = "usuarios-por-email", allEntries = true)
    })
    @Transactional
    public UsuarioResponse cambiarPassword(Integer id, CambiarPasswordRequest request) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));

        if (!passwordEncoder.matches(request.getPasswordActual(), usuario.getPasswordHash())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "La contrasena actual no es correcta");
        }
        if (passwordEncoder.matches(request.getPasswordNueva(), usuario.getPasswordHash())) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "La contrasena nueva debe ser distinta de la actual");
        }

        usuario.setPasswordHash(passwordEncoder.encode(request.getPasswordNueva()));
        usuario.setDebeCambiarPassword(false);
        usuarioRepository.save(usuario);
        log.info("Contrasena cambiada por el usuario id={}", usuario.getId());

        return UsuarioResponse.from(usuarioRepository.findByEmailWithRoles(usuario.getEmail())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado")));
    }

    /**
     * Reinicio de contrasena por un ADMIN. La clave la define el ADMIN y queda
     * marcada como temporal: el usuario debera cambiarla en su proximo ingreso.
     *
     * <p>No se admite reiniciar la propia cuenta por este camino: el ADMIN ya
     * tiene la pantalla de perfil, donde si se exige la clave actual. Eso evita
     * dejar su propia sesion con una clave que ya no conoce.
     */
    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#id"),
            @CacheEvict(cacheNames = "usuarios-por-email", allEntries = true)
    })
    @Transactional
    public UsuarioResponse reiniciarPassword(Integer id, Integer adminId,
                                             ReiniciarPasswordRequest request) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));

        if (usuario.getId().equals(adminId)) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "Para cambiar tu propia contrasena usa la pantalla de perfil");
        }
        if (passwordEncoder.matches(request.getPassword(), usuario.getPasswordHash())) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "La contrasena de reinicio debe ser distinta de la actual");
        }

        usuario.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        usuario.setDebeCambiarPassword(true);
        usuarioRepository.save(usuario);

        log.info("Contrasena reiniciada por admin id={} al usuario id={}, email={}",
                adminId, usuario.getId(), usuario.getEmail());

        notificacionService.enviarCredenciales(usuario.getEmail(), usuario.getNombre(),
                request.getPassword());

        return UsuarioResponse.from(usuarioRepository.findByEmailWithRoles(usuario.getEmail())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado")));
    }

    /**
     * Preferencia general del vendedor: emitir sus propias facturas o delegarlas
     * a un FUNCIONARIO. No hay autoasignacion de roles: solo cambia el modo de
     * facturacion de la propia cuenta.
     */
    @Caching(evict = {
            @CacheEvict(cacheNames = "usuarios", key = "#id"),
            @CacheEvict(cacheNames = "usuarios-por-email", allEntries = true)
    })
    @Transactional
    public UsuarioResponse actualizarModoFacturacion(Integer id, ModoFacturacionRequest request) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        usuario.setModoFacturacion(request.getModo());
        usuarioRepository.save(usuario);
        log.info("Modo de facturacion actualizado: id={}, modo={}", id, request.getModo());
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
                usuario.getEmail(), usuario.getNombre(), roles,
                Boolean.TRUE.equals(usuario.getDebeCambiarPassword()),
                usuario.getModoFacturacion());
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

    /**
     * Texto que ve el usuario al intentar entrar con una cuenta dada de baja.
     * Las cuentas desactivadas antes de este cambio no tienen motivo guardado:
     * en ese caso se responde sin inventar una razon.
     */
    private String mensajeCuentaDesactivada(Usuario usuario) {
        String motivo = usuario.getMotivoDesactivacion();
        if (motivo == null || motivo.isBlank()) {
            return "Tu cuenta fue desactivada. Contacta a un administrador para mas informacion.";
        }
        return "Tu cuenta fue desactivada. Motivo: " + motivo.trim();
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
        final LocalDateTime ultimoEnvio;
        int intentos;

        RegistroPendiente(String nombre, String email, String passwordHash, String telefono, String ruc,
                          String nombreRol, String codigoHash, LocalDateTime expiraEn, int intentos,
                          LocalDateTime ultimoEnvio) {
            this.nombre = nombre;
            this.email = email;
            this.passwordHash = passwordHash;
            this.telefono = telefono;
            this.ruc = ruc;
            this.nombreRol = nombreRol;
            this.codigoHash = codigoHash;
            this.expiraEn = expiraEn;
            this.intentos = intentos;
            this.ultimoEnvio = ultimoEnvio;
        }
    }

    private static class RecuperacionPendiente {
        final String codigoHash;
        final LocalDateTime expiraEn;
        final LocalDateTime ultimoEnvio;
        int intentos;

        RecuperacionPendiente(String codigoHash, LocalDateTime expiraEn, int intentos,
                              LocalDateTime ultimoEnvio) {
            this.codigoHash = codigoHash;
            this.expiraEn = expiraEn;
            this.intentos = intentos;
            this.ultimoEnvio = ultimoEnvio;
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
        public String motivoDesactivacion;
        public boolean debeCambiarPassword;
        public ModoFacturacion modoFacturacion;
        public List<String> roles = new ArrayList<>();

        public static UsuarioResponse from(Usuario u) {
            UsuarioResponse r = new UsuarioResponse();
            r.id = u.getId();
            r.nombre = u.getNombre();
            r.email = u.getEmail();
            r.telefono = u.getTelefono();
            r.ruc = u.getRuc();
            r.activo = Boolean.TRUE.equals(u.getActivo());
            r.motivoDesactivacion = u.getMotivoDesactivacion();
            r.debeCambiarPassword = Boolean.TRUE.equals(u.getDebeCambiarPassword());
            r.modoFacturacion = u.getModoFacturacion();
            r.roles.addAll(u.getRoles().stream().map(Rol::getName).sorted().toList());
            return r;
        }
    }

    public record PaginaUsuarios(List<UsuarioResponse> content, long totalElements,
                                 int totalPages, int number, int size) {}
}
