package com.honeypot.honeypot.service;

import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class EventoMapperTest {

    private final EventoMapper mapper = new EventoMapper();

    @Test
    @DisplayName("Convierte LoginAttempt al contrato comun SIEM con los 8 campos raiz")
    void shouldMapToSiemCommonContract() {
        Instant ahora = Instant.parse("2026-10-12T15:00:00.123456Z");

        LoginAttempt attempt = new LoginAttempt();
        // Sin setId(): attempt.getId() sera null y mapper generara "HP-0"
        attempt.setOccurredAt(ahora);
        attempt.setSourceIp("192.168.1.100");
        attempt.setServiceAttacked("honeypot-web");
        attempt.setUsername("admin");
        attempt.setCredentialAttempt("secreto123");
        attempt.setAttemptedCommand(null);
        attempt.setRequestPath("/login");
        attempt.setUserAgent("Mozilla/5.0");

        String eventType = "fuerza_bruta";
        String severity = "medium";

        EventoContrato evento = mapper.mapearAEvento(attempt, eventType, severity);

        assertEquals("HP-0", evento.eventId());
        assertEquals("2026-10-12T15:00:00Z", evento.timestamp());
        assertEquals("honeypot", evento.source());
        assertEquals("fuerza_bruta", evento.eventType());
        assertEquals("medium", evento.severity());
        assertEquals("Intento de acceso en el login falso", evento.title());
        assertEquals("Intento desde 192.168.1.100 con el usuario admin", evento.description());

        assertNotNull(evento.details());
        assertEquals("192.168.1.100", evento.details().get("source_ip"));
        assertEquals("honeypot-web", evento.details().get("service"));
        assertEquals("admin", evento.details().get("username"));
        assertEquals("secreto123", evento.details().get("credential"));
        assertNull(evento.details().get("command"));
        assertEquals("/login", evento.details().get("ruta"));
        assertEquals("Mozilla/5.0", evento.details().get("navegador"));
    }

    @Test
    @DisplayName("HP-77: un intento sin etiqueta se envia como intento_login")
    void sinEtiquetaSeEnviaComoIntentoLogin() {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setOccurredAt(Instant.parse("2026-10-27T12:00:00Z"));
        attempt.setSourceIp("192.168.1.100");
        attempt.setServiceAttacked("honeypot-web");

        EventoContrato evento = mapper.mapearAEvento(attempt, "medium");

        assertEquals("intento_login", evento.eventType());
    }

    @Test
    @DisplayName("HP-77: un intento etiquetado como fuerza_bruta se envia con esa etiqueta")
    void conEtiquetaSeEnviaLaEtiqueta() {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setOccurredAt(Instant.parse("2026-10-27T12:00:00Z"));
        attempt.setSourceIp("192.168.1.100");
        attempt.setServiceAttacked("honeypot-web");
        attempt.setTipoAtaque(ClasificadorAtaquesService.FUERZA_BRUTA);

        EventoContrato evento = mapper.mapearAEvento(attempt, "medium");

        assertEquals("fuerza_bruta", evento.eventType());
    }
}