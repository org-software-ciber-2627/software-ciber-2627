package com.honeypot.honeypot.service;

import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import tools.jackson.databind.json.JsonMapper;

@Service
public class DetectorEscaneoService {

    private static final Logger log = LoggerFactory.getLogger(DetectorEscaneoService.class);
    private static final String EVENT_TYPE = "escaneo";
    private static final long VENTANA_MINUTOS = 5;

    private final Map<String, EstadoIp> contactosPorIp = new LinkedHashMap<>();
    private final LoginAttemptRepository loginAttemptRepository;
    private final EventoMapper eventoMapper;
    private final SiemSenderService siemSenderService;
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    public DetectorEscaneoService(
            LoginAttemptRepository loginAttemptRepository,
            EventoMapper eventoMapper,
            SiemSenderService siemSenderService
    ) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.eventoMapper = eventoMapper;
        this.siemSenderService = siemSenderService;
    }

    public void registrarContacto(String ip, String servicio, Instant momento) {
        if (ip == null || ip.isBlank() || servicio == null || servicio.isBlank() || momento == null) {
            log.warn("No se pudo evaluar un contacto para detectar escaneos: faltan IP, servicio o momento");
            return;
        }

        List<String> serviciosDetectados;
        LoginAttempt intentoEscaneo;
        synchronized (this) {
            Instant limite = momento.minus(VENTANA_MINUTOS, ChronoUnit.MINUTES);
            EstadoIp estado = contactosPorIp.computeIfAbsent(ip, ignored -> new EstadoIp());
            estado.ultimosContactos.entrySet().removeIf(entry -> !entry.getValue().isAfter(limite));
            if (estado.ultimosContactos.size() < 2) {
                estado.eventoEmitido = false;
            }
            estado.ultimosContactos.put(servicio, momento);

            if (estado.ultimosContactos.size() < 2 || estado.eventoEmitido) {
                return;
            }

            estado.eventoEmitido = true;
            serviciosDetectados = List.copyOf(estado.ultimosContactos.keySet());
            intentoEscaneo = crearIntentoEscaneo(ip, momento, serviciosDetectados);
        }

        guardarYEnviar(intentoEscaneo, serviciosDetectados);
    }

    @Scheduled(fixedDelayString = "${honeypot.escaneo.limpieza-ms:60000}")
    public synchronized void limpiarContactosExpirados() {
        Instant limite = Instant.now().minus(VENTANA_MINUTOS, ChronoUnit.MINUTES);
        contactosPorIp.values().forEach(estado ->
                estado.ultimosContactos.entrySet().removeIf(entry -> !entry.getValue().isAfter(limite)));
        contactosPorIp.entrySet().removeIf(entry -> entry.getValue().ultimosContactos.isEmpty());
    }

    private LoginAttempt crearIntentoEscaneo(String ip, Instant momento, List<String> servicios) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setSourceIp(ip);
        attempt.setOccurredAt(momento);
        attempt.setServiceAttacked("honeypot-scan");
        attempt.setTipoAtaque(EVENT_TYPE);
        attempt.setAttemptedCommand(String.join(", ", servicios));
        return attempt;
    }

    private void guardarYEnviar(LoginAttempt attempt, List<String> servicios) {
        LoginAttempt guardado;
        try {
            guardado = loginAttemptRepository.save(attempt);
        } catch (RuntimeException e) {
            log.error("No se pudo guardar en la base de datos el evento de escaneo de la IP {}",
                    attempt.getSourceIp(), e);
            return;
        }

        EventoContrato evento = eventoMapper.mapearEventoEscaneo(guardado, servicios, VENTANA_MINUTOS);
        String json;
        try {
            json = jsonMapper.writeValueAsString(evento);
        } catch (Exception e) {
            log.error("No se pudo preparar el evento de escaneo {} para el SIEM", evento.eventId(), e);
            return;
        }

        CompletableFuture.runAsync(() -> {
            int statusCode = siemSenderService.enviarEvento(json, guardado.getId());
            if (SiemSenderService.esExito(statusCode)) {
                guardado.setEnviado(true);
                loginAttemptRepository.save(guardado);
                log.info("Evento de escaneo {} enviado al SIEM (HTTP {})", evento.eventId(), statusCode);
            } else {
                log.warn("El SIEM respondio con codigo {} para el evento de escaneo {}",
                        statusCode, evento.eventId());
            }
        }).exceptionally(error -> {
            log.error("Error procesando el evento de escaneo {}", evento.eventId(), error);
            return null;
        });
    }

    private static final class EstadoIp {
        private final Map<String, Instant> ultimosContactos = new LinkedHashMap<>();
        private boolean eventoEmitido;
    }
}
