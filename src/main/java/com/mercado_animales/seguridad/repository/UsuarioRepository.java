package com.mercado_animales.seguridad.repository;

import com.mercado_animales.usuario.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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
}
