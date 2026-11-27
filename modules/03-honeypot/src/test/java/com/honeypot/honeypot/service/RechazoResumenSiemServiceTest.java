package com.honeypot.honeypot.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.honeypot.honeypot.model.EventoPendiente;
import com.honeypot.honeypot.model.RechazoResumen;
import com.honeypot.honeypot.repository.EventoPendienteRepository;
import com.honeypot.honeypot.repository.RechazoResumenRepository;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

class RechazoResumenSiemServiceTest {

    private static final Instant MINUTO_CERRADO = Instant.parse("2026-11-17T12:04:00Z");
    private static final Instant AHORA = Instant.parse("2026-11-17T12:05:40Z");
    private static final Instant MINUTO_ACTUAL = Instant.parse("2026-11-17T12:05:00Z");

    private EventoPendienteRepository pendientes;
    private RechazoResumenRepository repositorio;
    private RechazoResumen fila;

    @BeforeEach
    void preparar() {
        pendientes = mock(EventoPendienteRepository.class);
        repositorio = mock(RechazoResumenRepository.class);
        fila = new RechazoResumen("198.51.100.50", MINUTO_CERRADO, "honeypot-web");
        fila.sumarRechazo();
        fila.sumarRechazo();
        fila.sumarRechazo();
        // El id lo pone la BD; aquí lo fijamos para poder comprobar el event_id
        ReflectionTestUtils.setField(fila, "id", 7L);
    }

    private RechazoResumenSiemService servicio(String url) {
        SiemSenderService sender = new SiemSenderService(pendientes);
        ReflectionTestUtils.setField(sender, "siemUrl", url);
        return new RechazoResumenSiemService(repositorio, sender);
    }

    // HP-104: un minuto ya cerrado se envía al SIEM con sus 8 campos y la fila queda marcada
    @Test
    void enviaElResumenDeUnMinutoCerradoYLoMarca() throws Exception {
        when(repositorio.findByEnviadoFalseAndMinutoBefore(MINUTO_ACTUAL)).thenReturn(List.of(fila));
        try (SiemFalso siem = new SiemFalso()) {
            int tratados = servicio(siem.url()).enviarResumenesAnterioresA(AHORA);

            assertEquals(1, tratados);
            assertEquals(1, siem.recibidos().size());
            String json = siem.recibidos().get(0);
            assertTrue(json.contains("\"event_id\":\"HP-R-7\""));
            assertTrue(json.contains("\"source\":\"honeypot\""));
            assertTrue(json.contains("\"rechazos\":3"));
            assertTrue(json.contains("\"source_ip\":\"198.51.100.50\""));
            assertTrue(json.contains("\"timestamp\":\"2026-11-17T12:04:00Z\""));
            assertTrue(fila.isEnviado());
            verify(repositorio).save(fila);
        }
    }

    // HP-114: el resumen sale con el event_type y la severidad acordados con el grupo 5
    @Test
    void elResumenSaleConEventTypeYSeveridadAcordados() throws Exception {
        when(repositorio.findByEnviadoFalseAndMinutoBefore(MINUTO_ACTUAL)).thenReturn(List.of(fila));
        try (SiemFalso siem = new SiemFalso()) {
            servicio(siem.url()).enviarResumenesAnterioresA(AHORA);

            String json = siem.recibidos().get(0);
            assertTrue(json.contains("\"event_type\":\"peticiones_rechazadas\""));
            assertTrue(json.contains("\"severity\":\"info\""));
        }
    }

    // HP-104: solo pide los minutos anteriores al actual (el actual aún puede seguir sumando)
    @Test
    void noEnviaNadaSiNoHayMinutosCerradosPendientes() throws Exception {
        // El mock solo devuelve la fila si se le pregunta por 12:05:00; con otra hora devuelve vacío
        when(repositorio.findByEnviadoFalseAndMinutoBefore(MINUTO_ACTUAL)).thenReturn(List.of());
        try (SiemFalso siem = new SiemFalso()) {
            int tratados = servicio(siem.url()).enviarResumenesAnterioresA(AHORA);

            assertEquals(0, tratados);
            assertTrue(siem.recibidos().isEmpty());
            verify(repositorio, never()).save(any());
        }
    }

    // HP-105: con el SIEM caído el resumen va a la cola de HP-22 y no se pierde
    @Test
    void siElSiemEstaCaidoElResumenVaALaCola() {
        when(repositorio.findByEnviadoFalseAndMinutoBefore(MINUTO_ACTUAL)).thenReturn(List.of(fila));

        servicio("http://127.0.0.1:1/events").enviarResumenesAnterioresA(AHORA);

        ArgumentCaptor<EventoPendiente> guardado = ArgumentCaptor.forClass(EventoPendiente.class);
        verify(pendientes).save(guardado.capture());
        assertTrue(guardado.getValue().getJson().contains("\"event_id\":\"HP-R-7\""));
        assertNull(guardado.getValue().getAttemptId());
        // Ya está a salvo en la cola, así que no se vuelve a generar cada minuto
        assertTrue(fila.isEnviado());
    }

    // Si el SIEM rechaza el resumen (4xx) no se reintenta: se marca y se sigue
    @Test
    void siElSiemRechazaElResumenNoSeReintenta() throws Exception {
        when(repositorio.findByEnviadoFalseAndMinutoBefore(MINUTO_ACTUAL)).thenReturn(List.of(fila));
        try (SiemFalso siem = new SiemFalso()) {
            siem.responderCon(422);

            servicio(siem.url()).enviarResumenesAnterioresA(AHORA);

            verify(pendientes, never()).save(any());
            assertTrue(fila.isEnviado());
        }
    }

    @Test
    void unResumenNuevoNoEstaEnviado() {
        assertFalse(new RechazoResumen("198.51.100.51", MINUTO_CERRADO, "ssh").isEnviado());
    }
}
