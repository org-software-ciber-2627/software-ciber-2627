package com.ciberurjc.siem.security;

/**
 * Valida un token Bearer contra el Módulo 1 (Identidad y secretos).
 * Contrato: modules/05-siem/contract/identity-auth.md (SEM-132).
 */
public interface IdentityValidator {

    /**
     * @param token el token recibido, sin el prefijo "Bearer "
     * @return la identidad confirmada por G1
     * @throws UnauthenticatedException si G1 rechaza el token (401)
     * @throws IdentityUnavailableException si no se puede confirmar la identidad
     */
    AuthenticatedIdentity validate(String token);
}
