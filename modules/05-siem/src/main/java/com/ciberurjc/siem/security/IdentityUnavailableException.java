package com.ciberurjc.siem.security;

/**
 * No se ha podido confirmar la identidad con G1. Se responde 503 sin conceder acceso (fail-closed).
 * retryLater indica si se añade la cabecera Retry-After (G1 caído, lento o con 5xx).
 */
public class IdentityUnavailableException extends RuntimeException {

    private final boolean retryLater;

    public IdentityUnavailableException(String message, boolean retryLater) {
        super(message);
        this.retryLater = retryLater;
    }

    public IdentityUnavailableException(String message, boolean retryLater, Throwable cause) {
        super(message, cause);
        this.retryLater = retryLater;
    }

    public boolean retryLater() {
        return retryLater;
    }
}
