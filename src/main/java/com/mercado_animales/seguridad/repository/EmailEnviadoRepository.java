package com.mercado_animales.seguridad.repository;

import com.mercado_animales.notificacion.EmailEnviado;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

/** Bandeja de correos enviados (solo lectura para la UI de ADMIN). */
public interface EmailEnviadoRepository
        extends JpaRepository<EmailEnviado, Integer>, JpaSpecificationExecutor<EmailEnviado> {
}
