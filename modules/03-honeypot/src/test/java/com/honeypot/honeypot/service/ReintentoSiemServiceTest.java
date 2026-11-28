package com.honeypot.honeypot.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.honeypot.honeypot.model.EventoPendiente;
import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.EventoPendienteRepository;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class ReintentoSiemServiceTest {

    private EventoPendienteRepository pendientes;
    private LoginAttemptRepository repositorio;
    private EventoPendiente primero;
    private EventoPendiente segundo;
    private EventoPendiente tercero;

    @BeforeEach
    void preparar() {
        pendientes = mock(EventoPendienteRepository.class);
        repositorio = mock(LoginAttemptRepository.class);
        primero = new EventoPendiente("{\"event_id\":\"HP-1\"}", 1L);
        segundo = new EventoPendiente("{\"event_id\":\"HP-2\"}", 2L);
        tercero = new EventoPendiente("{\"event_id\":\"HP-3\"}", 3L);
        when(pendientes.findTop100ByOrderByIdAsc()).thenReturn(List.of(primero, segundo, tercero));
    }

    private ReintentoSiemService reintento(String url) {
        SiemSenderService sender = new SiemSenderService(pendientes);
        ReflectionTestUtils.setField(sender, "siemUrl", url);
        return new ReintentoSiemService(pendientes, repositorio, sender);
    }

    // HP-22: cuando el SIEM vuelve, los pendientes llegan en orden y el intento queda como enviado
    @Test
    void cuandoElSiemVuelveLosPendientesLleganEnOrden() throws Exception {
        LoginAttempt intento = new LoginAttempt();
        when(repositorio.findById(1L)).thenReturn(Optional.of(intento));
        try (SiemFalso siem = new SiemFalso()) {
            int enviados = reintento(siem.url()).reintentarPendientes();

            assertEquals(3, enviados);
            assertEquals(List.of(primero.getJson(), segundo.getJson(), tercero.getJson()), siem.recibidos());
            verify(pendientes).delete(primero);
            verify(pendientes).delete(segundo);
            verify(pendientes).delete(tercero);
            assertTrue(intento.isEnviado());
        }
    }

    @Test
    void siElSiemSigueCaidoNoSeBorraNingunPendiente() {
        int enviados = reintento("http://127.0.0.1:1/events").reintentarPendientes();

        assertEquals(0, enviados);
        verify(pendientes, never()).delete(primero);
        verify(pendientes, never()).delete(segundo);
        verify(pendientes, never()).delete(tercero);
    }

    // HP-22: si uno falla, no se envían los siguientes para no desordenarlos
    @Test
    void siFallaUnoSeParaParaNoDesordenar() throws Exception {
        try (SiemFalso siem = new SiemFalso()) {
            siem.responderCon(200, 503);

            int enviados = reintento(siem.url()).reintentarPendientes();

            assertEquals(1, enviados);
            assertEquals(List.of(primero.getJson()), siem.recibidos());
            verify(pendientes).delete(primero);
            verify(pendientes, never()).delete(segundo);
            verify(pendientes, never()).delete(tercero);
        }
    }

    // Un evento rechazado (400) se descarta y se sigue con los demás
    @Test
    void unEventoRechazadoSeDescartaYSigueConLosDemas() throws Exception {
        try (SiemFalso siem = new SiemFalso()) {
            siem.responderCon(200, 400, 200);

            int enviados = reintento(siem.url()).reintentarPendientes();

            assertEquals(2, enviados);
            assertEquals(List.of(primero.getJson(), tercero.getJson()), siem.recibidos());
            verify(pendientes).delete(segundo);
        }
    }
}
