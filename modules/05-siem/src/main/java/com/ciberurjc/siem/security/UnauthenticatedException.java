package com.ciberurjc.siem.security;

/** G1 ha rechazado el token: ausente, inválido, expirado o revocado. Se responde 401. */
public class UnauthenticatedException extends RuntimeException {

    public UnauthenticatedException(String message) {
        super(message);
    }
}
