package com.mercado_animales.seguridad.security;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

/**
 * Principal autenticado del servicio de seguridad.
 *
 * <p>Antes el principal era el email (String), asi que {@code @PreAuthorize}
 * no podia comparar el id de la ruta con el del token. Con este objeto ya se
 * puede autorizar "ADMIN o el propio usuario".
 */
@Getter
@AllArgsConstructor
public class UsuarioAutenticado {

    private final Integer id;
    private final String email;
    private final List<String> roles;
}
