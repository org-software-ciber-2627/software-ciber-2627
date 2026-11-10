package com.honeypot.honeypot.service;

import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.json.JsonMapper;

@Service
public class FtpEventService {

    private static final Logger log = LoggerFactory.getLogger(FtpEventService.class);
    private static final String REDACTED = "[REDACTED]";

    
    private static final String EVENT_TYPE_NORMAL = "intento_login";

    private final LoginAttemptRepository loginAttemptRepository;
    private final EventoMapper eventoMapper;
    private final SiemSenderService siemSenderService;
    private final ClasificadorAtaquesService clasificadorAtaquesService;
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    public FtpEventService(
            LoginAttemptRepository loginAttemptRepository,
            EventoMapper eventoMapper,
            SiemSenderService siemSenderService,
            ClasificadorAtaquesService clasificadorAtaquesService
    ) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.eventoMapper = eventoMapper;
        this.siemSenderService = siemSenderService;
        this.clasificadorAtaquesService = clasificadorAtaquesService;
    }

    public void registrarComando(String sourceIp, String command, String argument) {

        LoginAttempt attempt = new LoginAttempt();

        attempt.setSourceIp(truncate(sourceIp, 64));
        attempt.setOccurredAt(Instant.now());
        attempt.setServiceAttacked("ftp");
        attempt.setRequestPath(null);
        attempt.setUserAgent(null);

        boolean passwordCommand = "PASS".equals(command);

        if ("USER".equals(command)) {
            attempt.setUsername(truncate(argument, 320));
        } else if (passwordCommand) {
            attempt.setCredentialAttempt(REDACTED);
            attempt.setPasswordLength(argument == null ? null : argument.length());
        }

        String attemptedCommand = passwordCommand
                ? "PASS " + REDACTED
                : argument == null || argument.isBlank()
                    ? command
                    : command + " " + argument;

        attempt.setAttemptedCommand(truncate(attemptedCommand, 2000));

       
        String tipoAtaque = null;

        if (passwordCommand) {
            // En el FTP el usuario y la contraseña llegan en comandos distintos (USER y PASS),
            // así que de momento no se comprueban las credenciales por defecto
            tipoAtaque = clasificadorAtaquesService.clasificar(
                    attempt.getSourceIp(),
                    attempt.getOccurredAt(),
                    null,
                    null
            );

            attempt.setTipoAtaque(tipoAtaque);
        }

        attempt = loginAttemptRepository.save(attempt);

        String eventType = tipoAtaque != null
                ? tipoAtaque
                : EVENT_TYPE_NORMAL;

        String severity = passwordCommand ? "medium" : "low";

        try {
            EventoContrato evento = eventoMapper.mapearAEvento(
                    attempt,
                    eventType,
                    severity
            );

            String json = jsonMapper.writeValueAsString(evento);
            LoginAttempt savedAttempt = attempt;

            CompletableFuture.runAsync(() -> enviarAlSiem(
                    json,
                    evento,
                    savedAttempt
            )).exceptionally(e -> {
                log.error(
                        "Error procesando el evento FTP {} en segundo plano",
                        evento.eventId(),
                        e
                );
                return null;
            });

        } catch (Exception e) {
            log.error(
                    "No se pudo preparar el evento FTP {} para el SIEM",
                    attempt.getId(),
                    e
            );
        }
    }

    private void enviarAlSiem(
            String json,
            EventoContrato evento,
            LoginAttempt attempt
    ) {
        int statusCode = siemSenderService.enviarEvento(json);

        if (statusCode == 200 || statusCode == 201) {
            attempt.setEnviado(true);
            loginAttemptRepository.save(attempt);

            log.info(
                    "Evento FTP {} enviado al SIEM (HTTP {})",
                    evento.eventId(),
                    statusCode
            );
        } else {
            log.warn(
                    "El SIEM respondio con codigo {} para el evento FTP {}",
                    statusCode,
                    evento.eventId()
            );
        }
    }

    private static String truncate(String value, int maxLength) {
        return value == null || value.length() <= maxLength
                ? value
                : value.substring(0, maxLength);
    }
}