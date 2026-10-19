package com.mercado_animales.seguridad.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    /**
     * Base publica que usa el boton "Try it out" de Swagger.
     *
     * Es relativa a proposito: el navegador la resuelve contra el origen desde
     * el que sirve la UI (el gateway), asi las peticiones salen por
     * http://<gateway>/seguridad-ms/... y no directo al puerto 8084.
     *
     * Vacia ("") = dejar que Springdoc detecte la URL (util si se abre el
     * Swagger del propio microservicio).
     */
    @Value("${app.openapi.server-url:/seguridad-ms}")
    private String serverUrl;

    @Bean
    public OpenAPI seguridadOpenApi() {
        OpenAPI openApi = new OpenAPI()
            .info(new Info().title("Mercado Animales - Seguridad").version("1.0")
                .description("Login, registro, verificacion y gestion de usuarios/roles"))
            .components(new Components().addSecuritySchemes("bearerAuth", new SecurityScheme()
                .type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")))
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));

        if (serverUrl != null && !serverUrl.isBlank()) {
            openApi.servers(List.of(new Server().url(serverUrl).description("API Gateway")));
        }
        return openApi;
    }
}
