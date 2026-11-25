package com.honeypot.honeypot.ssh;

import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import com.honeypot.honeypot.service.ClasificadorAtaquesService;
import com.honeypot.honeypot.service.EventoMapper;
import com.honeypot.honeypot.service.SiemSenderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.util.concurrent.CompletableFuture;

/**
 * Guarda cada intento SSH en la BD y lo envía al SIEM (HP-67).
 * Sigue el mismo flujo que el login web y el FTP: clasificar, guardar y enviar con el EventoMapper.
 */
@Component
public class SshAttemptRecorder implements SshAttemptListener {

    private static final Logger log = LoggerFactory.getLogger(SshAttemptRecorder.class);

    static final String SERVICE_NAME = "honeypot-ssh";

    private final LoginAttemptRepository repository;
    private final ClasificadorAtaquesService clasificador;
    private final EventoMapper eventoMapper;
    private final SiemSenderService siemSenderService;
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    public SshAttemptRecorder(LoginAttemptRepository repository,
                              ClasificadorAtaquesService clasificador,
                              EventoMapper eventoMapper,
                              SiemSenderService siemSenderService) {
        this.repository = repository;
        this.clasificador = clasificador;
        this.eventoMapper = eventoMapper;
        this.siemSenderService = siemSenderService;
    }

    @Override
    public void onAttempt(SshAttemptData data) {
        LoginAttempt attempt = toLoginAttempt(data);

        // 1. Clasificar antes de guardar, como el login y el FTP (HP-12 y HP-25)
        attempt.setTipoAtaque(clasificador.clasificar(attempt.getSourceIp(), attempt.getOccurredAt(),
                attempt.getUsername(), attempt.getCredentialAttempt()));

        // 2. Guardar
        repository.save(attempt);

        // La contraseña no se escribe en el log a propósito
        log.info("Intento SSH guardado: ip={} usuario={} metodo={} tipo={}",
                attempt.getSourceIp(), limpiar(attempt.getUsername()), data.authMethod(),
                EventoMapper.tipoDeEvento(attempt));

        // 3. Envío al SIEM en segundo plano
        enviarAlSiem(attempt);
    }

    LoginAttempt toLoginAttempt(SshAttemptData data) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setSourceIp(data.sourceIp());
        attempt.setOccurredAt(data.occurredAt());
        attempt.setServiceAttacked(SERVICE_NAME);
        attempt.setUsername(truncate(data.username(), 320));
        attempt.setUserAgent(truncate(data.clientVersion(), 512));

        if (data.authMethod() == SshAttemptData.AuthMethod.PASSWORD) {
            attempt.setCredentialAttempt(truncate(data.password(), 2000));
            attempt.setPasswordLength(data.password() == null ? null : data.password().length());
        } else {
            // La huella de la clave no es una contraseña: va en attemptedCommand para que no cuente
            // como intento en la fuerza bruta (el cliente ssh prueba sus claves antes de pedir contraseña)
            attempt.setAttemptedCommand(truncate("publickey " + data.publicKeyFingerprint(), 2000));
        }
        return attempt;
    }

    private void enviarAlSiem(LoginAttempt attempt) {
        CompletableFuture.runAsync(() -> {
            try {
                // Severidad "high" para credenciales por defecto, como en el login web
                String severidad = ClasificadorAtaquesService.CREDENCIALES_POR_DEFECTO
                        .equals(attempt.getTipoAtaque()) ? "high" : "medium";
                EventoContrato evento = eventoMapper.mapearAEvento(attempt, severidad);
                String json = jsonMapper.writeValueAsString(evento);
                int statusCode = siemSenderService.enviarEvento(json);

                if (statusCode == 200 || statusCode == 201) {
                    attempt.setEnviado(true);
                    repository.save(attempt);
                    log.info("Evento {} enviado al SIEM con exito (HTTP {})", evento.eventId(), statusCode);
                } else {
                    log.warn("El SIEM respondio con codigo no exitoso: {} para el evento {}", statusCode, evento.eventId());
                }
            } catch (Exception e) {
                log.warn("Error al procesar o enviar evento SSH al SIEM: {}", e.getMessage());
            }
        });
    }

    private static String truncate(String value, int maxLength) {
        return value == null || value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    // Evita log injection con usuarios que contengan saltos de línea
    private static String limpiar(String value) {
        return value == null ? null : value.replaceAll("[\\r\\n]", "_");
    }
}
