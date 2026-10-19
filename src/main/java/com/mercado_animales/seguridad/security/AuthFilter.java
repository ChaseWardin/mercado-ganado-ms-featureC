package com.mercado_animales.seguridad.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class AuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final String internalToken;

    public AuthFilter(JwtService jwtService, @Value("${app.internal.token}") String internalToken) {
        this.jwtService = jwtService;
        this.internalToken = internalToken;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                   FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtService.esValido(token)) {
                var authorities = jwtService.extraerRoles(token).stream()
                        .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                        .toList();
                if (authorities.isEmpty()) authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
                Long uid = jwtService.extraerUid(token);
                var principal = new UsuarioAutenticado(
                        uid == null ? null : uid.intValue(),
                        jwtService.extraerEmail(token),
                        jwtService.extraerRoles(token));
                var authentication = new UsernamePasswordAuthenticationToken(
                        principal, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } else {
            String apiKey = request.getHeader("X-Internal-Token");
            if (apiKey != null && apiKey.equals(internalToken)) {
                var authentication = new UsernamePasswordAuthenticationToken(
                        "service", null, List.of(new SimpleGrantedAuthority("ROLE_SERVICE")));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
