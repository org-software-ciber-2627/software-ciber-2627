package com.honeypot.honeypot.ssh;

/**
 * Recibe cada intento de acceso al señuelo SSH.
 * Para guardar en BD o enviar al SIEM, basta con crear un @Component que implemente esta interfaz.
 */
public interface SshAttemptListener {
    void onAttempt(SshAttemptData attempt);
} 
