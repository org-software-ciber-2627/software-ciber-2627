package com.honeypot.honeypot.ssh;

import java.time.Instant;

/**
 * Datos en bruto de un intento de acceso al señuelo SSH.
 * No depende de ninguna entidad: la conversión a BD se hará fuera de este paquete.
 */
public record SshAttemptData(
        String sourceIp,
        Integer sourcePort,
        Instant occurredAt,
        String username,
        AuthMethod authMethod,
        String password,          // null si el intento es por clave pública
        String publicKeyFingerprint, // null si el intento es por contraseña
        String clientVersion      // p. ej. "SSH-2.0-OpenSSH_9.5" o "SSH-2.0-libssh2_1.10.0"
) {
    public enum AuthMethod { PASSWORD, PUBLIC_KEY }
}
