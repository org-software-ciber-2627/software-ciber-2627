package com.honeypot.honeypot.repository;

import com.honeypot.honeypot.model.LoginAttempt;
import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    /**
     * Cuenta los intentos de una IP posteriores a un momento dado (HP-75).
     * Cuenta todos los servicios señuelo juntos: login web, SSH y FTP.
     * Solo cuenta las filas con contraseña (credential_attempt no nulo), porque el FTP
     * guarda también los comandos USER, LIST... y esos no son intentos de login (HP-78).
     */
    long countBySourceIpAndOccurredAtAfterAndCredentialAttemptIsNotNull(String sourceIp, Instant desde);
}