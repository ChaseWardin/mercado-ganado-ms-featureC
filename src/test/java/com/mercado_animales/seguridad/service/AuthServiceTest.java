package com.mercado_animales.seguridad.service;

import com.mercado_animales.seguridad.exception.ApiException;
import com.mercado_animales.seguridad.repository.RolRepository;
import com.mercado_animales.seguridad.repository.UsuarioRepository;
import com.mercado_animales.seguridad.repository.UsuarioRolRepository;
import com.mercado_animales.seguridad.security.JwtService;
import com.mercado_animales.usuario.Usuario;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Recuperacion de contrasena y espera entre reenvios.
 *
 * <p>No levanta Spring: el flujo es de memoria y las dependencias se mockean.
 * Asi se prueba lo que importa sin necesitar Neon ni SMTP: que no se filtre si
 * un correo existe, que el codigo correcto cambie la clave y que no se pueda
 * pedir un codigo nuevo antes de la espera.
 */
class AuthServiceTest {

    private UsuarioRepository usuarioRepository;
    private NotificacionService notificacionService;
    private PasswordEncoder passwordEncoder;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        usuarioRepository = mock(UsuarioRepository.class);
        RolRepository rolRepository = mock(RolRepository.class);
        UsuarioRolRepository usuarioRolRepository = mock(UsuarioRolRepository.class);
        JwtService jwtService = mock(JwtService.class);
        notificacionService = mock(NotificacionService.class);
        passwordEncoder = new BCryptPasswordEncoder(4);

        authService = new AuthService(usuarioRepository, rolRepository, usuarioRolRepository,
                passwordEncoder, jwtService, notificacionService);
    }

    private Usuario usuarioActivo() {
        Usuario usuario = new Usuario();
        usuario.setId(1);
        usuario.setNombre("Ana");
        usuario.setEmail("ana@ejemplo.com");
        usuario.setPasswordHash(passwordEncoder.encode("claveVieja1"));
        usuario.setActivo(true);
        usuario.setFechaRegistro(LocalDate.now());
        return usuario;
    }

    @Test
    void laRecuperacionRespondeIgualExistaONoElCorreo() {
        when(usuarioRepository.findByEmail("desconocido@ejemplo.com")).thenReturn(Optional.empty());

        String primera = authService.solicitarRecuperacion("desconocido@ejemplo.com");
        String segunda = authService.solicitarRecuperacion("desconocido@ejemplo.com");

        assertEquals(primera, segunda);
        verifyNoInteractions(notificacionService);
    }

    @Test
    void elCodigoValidoCambiaLaClaveYLaMarcaComoPropia() {
        Usuario usuario = usuarioActivo();
        when(usuarioRepository.findByEmail("ana@ejemplo.com")).thenReturn(Optional.of(usuario));
        when(usuarioRepository.save(any(Usuario.class))).thenAnswer(inv -> inv.getArgument(0));

        authService.solicitarRecuperacion("ana@ejemplo.com");

        ArgumentCaptor<String> codigo = ArgumentCaptor.forClass(String.class);
        verify(notificacionService).enviarRecuperacion(eq("ana@ejemplo.com"), eq("Ana"), codigo.capture());

        String mensaje = authService.restablecerPassword(
                "ana@ejemplo.com", codigo.getValue(), "claveNueva123");

        assertTrue(mensaje.toLowerCase().contains("actualizada"));
        assertTrue(passwordEncoder.matches("claveNueva123", usuario.getPasswordHash()));
        assertFalse(usuario.getDebeCambiarPassword());
    }

    @Test
    void unCodigoIncorrectoNoCambiaLaClave() {
        Usuario usuario = usuarioActivo();
        when(usuarioRepository.findByEmail("ana@ejemplo.com")).thenReturn(Optional.of(usuario));

        authService.solicitarRecuperacion("ana@ejemplo.com");

        ArgumentCaptor<String> codigo = ArgumentCaptor.forClass(String.class);
        verify(notificacionService).enviarRecuperacion(eq("ana@ejemplo.com"), eq("Ana"), codigo.capture());

        // Se arma un codigo que seguro no es el enviado, para no depender de
        // que el azar no genere justo ese numero.
        String incorrecto = "000000".equals(codigo.getValue()) ? "000001" : "000000";

        assertThrows(ApiException.class, () ->
                authService.restablecerPassword("ana@ejemplo.com", incorrecto, "claveNueva123"));
        assertTrue(passwordEncoder.matches("claveVieja1", usuario.getPasswordHash()));
    }

    @Test
    void noSeEnviaOtroCodigoAntesDeLaEspera() {
        Usuario usuario = usuarioActivo();
        when(usuarioRepository.findByEmail("ana@ejemplo.com")).thenReturn(Optional.of(usuario));

        authService.solicitarRecuperacion("ana@ejemplo.com");
        authService.solicitarRecuperacion("ana@ejemplo.com");

        verify(notificacionService, times(1))
                .enviarRecuperacion(eq("ana@ejemplo.com"), anyString(), anyString());
    }

    @Test
    void unaCuentaInactivaNoRecibeCodigo() {
        Usuario usuario = usuarioActivo();
        usuario.setActivo(false);
        when(usuarioRepository.findByEmail("ana@ejemplo.com")).thenReturn(Optional.of(usuario));

        String mensaje = authService.solicitarRecuperacion("ana@ejemplo.com");

        assertTrue(mensaje.toLowerCase().contains("si el correo esta registrado"));
        verifyNoInteractions(notificacionService);
    }
}
