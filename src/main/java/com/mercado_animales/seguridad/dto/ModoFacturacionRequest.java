package com.mercado_animales.seguridad.dto;

import com.mercado_animales.usuario.ModoFacturacion;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

/** Cambio de la preferencia general de facturacion del propio usuario. */
@Getter
@Setter
public class ModoFacturacionRequest {

    @NotNull(message = "el modo de facturacion es obligatorio")
    private ModoFacturacion modo;
}
