package com.mercado_animales.seguridad.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Maneja el vinculo usuario-rol sobre la tabla asociativa {@code usuarios_roles}.
 *
 * <p>La PK es compuesta (usuario_id, rol_id), asi que volver a agregar un rol
 * que quedo dado de baja no es un INSERT sino un UPDATE que lo reactiva
 * (mismo criterio que Favorito.reactivar()).
 */
@Repository
@RequiredArgsConstructor
public class UsuarioRolRepository {

    private final JdbcTemplate jdbc;

    /** Da de baja un rol sin borrar la fila. Devuelve 0 si no estaba activo. */
    public int desactivar(Integer usuarioId, Integer rolId) {
        return jdbc.update("UPDATE usuarios_roles SET activo = false "
                        + "WHERE usuario_id = ? AND rol_id = ? AND activo = true",
                usuarioId, rolId);
    }

    /** Reactiva un rol dado de baja, o lo agrega si nunca lo tuvo. */
    public int reactivar(Integer usuarioId, Integer rolId) {
        return jdbc.update("INSERT INTO usuarios_roles (usuario_id, rol_id, fecha_agregado, activo) "
                        + "VALUES (?, ?, now(), true) "
                        + "ON CONFLICT (usuario_id, rol_id) DO UPDATE "
                        + "SET activo = true, fecha_agregado = now()",
                usuarioId, rolId);
    }
}
