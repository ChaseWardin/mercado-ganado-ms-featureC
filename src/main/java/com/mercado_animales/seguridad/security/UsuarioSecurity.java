package com.mercado_animales.seguridad.security;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Apoyo para expresiones SpEL de {@code @PreAuthorize}.
 *
 * <p>Se usa un bean y no {@code authentication.principal.id} directo porque el
 * principal puede ser otro tipo (por ejemplo el usuario "service" del token
 * interno) y la expresion reventaria con un 500 en vez de denegar.
 */
@Component("usuarioSecurity")
public class UsuarioSecurity {

    public boolean esPropietario(Integer id, Authentication authentication) {
        return authentication != null
                && authentication.getPrincipal() instanceof UsuarioAutenticado usuario
                && id != null
                && id.equals(usuario.getId());
    }
}
