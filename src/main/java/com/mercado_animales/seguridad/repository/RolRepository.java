package com.mercado_animales.seguridad.repository;

import com.mercado_animales.usuario.Rol;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RolRepository extends JpaRepository<Rol, Integer> {

    Optional<Rol> findByName(String name);
}
