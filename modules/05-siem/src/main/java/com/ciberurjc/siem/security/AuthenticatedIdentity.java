package com.ciberurjc.siem.security;

/**
 * Identidad confirmada por el Módulo 1 (G1) mediante GET /auth/validate.
 * Nunca contiene el token.
 */
public record AuthenticatedIdentity(String username, String role, Long userId) {

    /** Atributo de la petición donde el filtro guarda la identidad validada (lo usará SEM-35). */
    public static final String REQUEST_ATTRIBUTE = AuthenticatedIdentity.class.getName();
}
