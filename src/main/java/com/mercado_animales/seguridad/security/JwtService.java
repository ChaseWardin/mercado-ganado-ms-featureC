package com.mercado_animales.seguridad.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {
    private final SecretKey key;
    private final long expirationMs;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.expiration-ms}") long expirationMs) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    public String generarToken(String email, Integer uid, List<String> roles) {
        Date ahora = new Date();
        return Jwts.builder()
                .subject(email)
                .claim("uid", uid)
                .claim("roles", roles)
                .issuedAt(ahora)
                .expiration(new Date(ahora.getTime() + expirationMs))
                .signWith(key)
                .compact();
    }

    public boolean esValido(String token) {
        try {
            Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
            Date exp = claims.getExpiration();
            return exp == null || exp.after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public String extraerEmail(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().getSubject();
    }

    @SuppressWarnings("unchecked")
    public java.util.List<String> extraerRoles(String token) {
        Object roles = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().get("roles");
        return roles instanceof List<?> lista ? lista.stream().map(String::valueOf).toList() : List.of();
    }

    public Long extraerUid(String token) {
        Object uid = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().get("uid");
        return uid instanceof Number n ? n.longValue() : null;
    }
}
