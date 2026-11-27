package com.honeypot.honeypot.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.honeypot.honeypot.model.EventoPendiente;
import com.honeypot.honeypot.repository.EventoPendienteRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

class SiemSenderServiceTest {

    // En el puerto 1 no escucha nadie: es como tener el SIEM caído
    private static final String SIEM_CAIDO = "http://127.0.0.1:1/events";

    private EventoPendienteRepository pendientes;

    @BeforeEach
    void preparar() {
        pendientes = mock(EventoPendienteRepository.class);
        when(pendientes.count()).thenReturn(0L);
    }

    private SiemSenderService sender(String url) {
        SiemSenderService sender = new SiemSenderService(pendientes);
        ReflectionTestUtils.setField(sender, "siemUrl", url);
        return sender;
    }

    // HP-22: si el SIEM no responde, el evento se guarda como pendiente
    @Test
    void siElSiemNoRespondeElEventoQuedaPendiente() {
        int codigo = sender(SIEM_CAIDO).enviarEvento("{\"event_id\":\"HP-1\"}", 1L);

        assertEquals(-1, codigo);
        ArgumentCaptor<EventoPendiente> guardado = ArgumentCaptor.forClass(EventoPendiente.class);
        verify(pendientes).save(guardado.capture());
        assertEquals("{\"event_id\":\"HP-1\"}", guardado.getValue().getJson());
        assertEquals(Long.valueOf(1L), guardado.getValue().getAttemptId());
    }

    // HP-22: si el SIEM da error (503, sin almacenamiento), el evento se guarda como pendiente
    @Test
    void siElSiemDaErrorElEventoQuedaPendiente() throws Exception {
        try (SiemFalso siem = new SiemFalso()) {
            siem.responderCon(503);

            int codigo = sender(siem.url()).enviarEvento("{\"event_id\":\"HP-2\"}", 2L);

            assertEquals(503, codigo);
            verify(pendientes).save(any(EventoPendiente.class));
        }
    }

    @Test
    void siElSiemAceptaElEventoNoQuedaPendiente() throws Exception {
        try (SiemFalso siem = new SiemFalso()) {
            int codigo = sender(siem.url()).enviarEvento("{\"event_id\":\"HP-3\"}", 3L);

            assertEquals(200, codigo);
            assertEquals(1, siem.recibidos().size());
            verify(pendientes, never()).save(any(EventoPendiente.class));
        }
    }

    // Contrato con el grupo 5: 400 y 507 no se reintentan
    @Test
    void siElSiemRechazaElEventoNoQuedaPendiente() throws Exception {
        try (SiemFalso siem = new SiemFalso()) {
            siem.responderCon(400, 507);

            assertEquals(400, sender(siem.url()).enviarEvento("{}", 4L));
            assertEquals(507, sender(siem.url()).enviarEvento("{}", 5L));
            verify(pendientes, never()).save(any(EventoPendiente.class));
        }
    }

    // HP-22: con pendientes en cola, el evento nuevo no se envía antes que ellos
    @Test
    void siHayPendientesElNuevoVaDetras() throws Exception {
        when(pendientes.count()).thenReturn(1L);
        try (SiemFalso siem = new SiemFalso()) {
            int codigo = sender(siem.url()).enviarEvento("{\"event_id\":\"HP-6\"}", 6L);

            assertEquals(-1, codigo);
            assertTrue(siem.recibidos().isEmpty());
            verify(pendientes).save(any(EventoPendiente.class));
        }
    }
}
