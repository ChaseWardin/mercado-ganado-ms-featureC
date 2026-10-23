package com.mercado_animales.seguridad.repository;

import com.mercado_animales.usuario.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Acceso a la tabla {@code usuarios}. Este microservicio es el UNICO que escribe
 * usuarios; los demas solo leen el JWT.
 */
public interface UsuarioRepository extends JpaRepository<Usuario, Integer>, JpaSpecificationExecutor<Usuario> {

    Optional<Usuario> findByEmail(String email);

    boolean existsByEmail(String email);

    /**
     * Carga el usuario con sus roles YA inicializados.
     *
     * <p>La coleccion de roles es {@code @ManyToMany(fetch = LAZY)}: un
     * {@code findByEmail} normal cierra la sesion de Hibernate y tocar despues
     * {@code getRoles()} revienta con LazyInitializationException. Por eso todo
     * lo que arma el token (que necesita las autoridades) usa este metodo.
     *
     * <p>LEFT y no INNER: un usuario sin roles activos debe volver con el Set
     * vacio, no desaparecer del resultado.
     */
    @Query("SELECT u FROM Usuario u LEFT JOIN FETCH u.roles WHERE u.email = :email")
    Optional<Usuario> findByEmailWithRoles(@Param("email") String email);

    /**
     * Igual que {@link #findByEmailWithRoles(String)} pero por id. La respuesta
     * de {@code UsuarioResponse} siempre incluye roles; con un {@code findById}
     * normal esa lectura inicializaba la coleccion LAZY con un SELECT extra.
     */
    @Query("SELECT u FROM Usuario u LEFT JOIN FETCH u.roles WHERE u.id = :id")
    Optional<Usuario> findByIdWithRoles(@Param("id") Integer id);

    /**
     * Inicializa los roles de toda una pagina en UNA consulta. Sin esto,
     * {@code listarUsuarios} disparaba un SELECT de roles por cada fila.
     */
    @Query("SELECT DISTINCT u FROM Usuario u LEFT JOIN FETCH u.roles WHERE u.id IN :ids")
    List<Usuario> findByIdInWithRoles(@Param("ids") Collection<Integer> ids);
}
