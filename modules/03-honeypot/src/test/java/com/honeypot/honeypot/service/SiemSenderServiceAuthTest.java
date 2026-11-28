package com.honeypot.honeypot.service;

import com.honeypot.honeypot.model.EventoPendiente;
import com.honeypot.honeypot.repository.EventoPendienteRepository;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SiemSenderServiceAuthTest {

    private static final String SAMPLE_EVENT =
            "{\"event_id\":\"hp-evt-001\",\"timestamp\":\"2026-11-26T18:00:00Z\",\"source\":\"honeypot\",\"event_type\":\"fuerza_bruta\",\"severity\":\"high\"}";

    private EventoPendienteRepository pendientes;
    private IdentidadAuthService authService;
    private HttpClient httpClient;
    private SiemSenderService senderService;

    @BeforeEach
    void setUp() {
        pendientes = mock(EventoPendienteRepository.class);
        authService = mock(IdentidadAuthService.class);
        httpClient = mock(HttpClient.class);
        senderService = new SiemSenderService(pendientes, authService, httpClient, "http://siem:80/events");
    }

    @Test
    @SuppressWarnings("unchecked")
    void enviaCabeceraBearerYValidaAcuse200ConMismoEventId() throws Exception {
        when(pendientes.count()).thenReturn(0L);
        when(authService.getToken()).thenReturn("token-valido");

        HttpResponse<String> okResponse = mockResponse(200, "{\"status\":\"accepted\",\"event_id\":\"hp-evt-001\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(okResponse);

        int status = senderService.enviarEvento(SAMPLE_EVENT, 10L);

        assertEquals(200, status);
        verify(pendientes, never()).save(any());

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient, times(1)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals("Bearer token-valido", captor.getValue().headers().firstValue("Authorization").orElse(""));
    }

    @Test
    @SuppressWarnings("unchecked")
    void ante200ConEventIdDistintoRechazaAcuseYGuardaEnCola() throws Exception {
        when(pendientes.count()).thenReturn(0L);
        when(authService.getToken()).thenReturn("token-valido");

        HttpResponse<String> badAckResponse = mockResponse(200, "{\"status\":\"accepted\",\"event_id\":\"otro-id-999\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(badAckResponse);

        int status = senderService.enviarEvento(SAMPLE_EVENT, 15L);

        assertEquals(-1, status);
        ArgumentCaptor<EventoPendiente> captor = ArgumentCaptor.forClass(EventoPendiente.class);
        verify(pendientes, times(1)).save(captor.capture());
        assertEquals(SAMPLE_EVENT, captor.getValue().getJson());
        assertEquals(15L, captor.getValue().getAttemptId());
    }

    @Test
    @SuppressWarnings("unchecked")
    void ante401RenuevaTokenYReintentaUnaSolaVez() throws Exception {
        when(pendientes.count()).thenReturn(0L);
        when(authService.getToken()).thenReturn("token-caducado", "token-renovado");

        HttpResponse<String> res401 = mockResponse(401, "{\"error\":\"unauthorized\"}");
        HttpResponse<String> res200 = mockResponse(200, "{\"status\":\"accepted\",\"event_id\":\"hp-evt-001\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(res401, res200);

        int status = senderService.enviarEvento(SAMPLE_EVENT, 11L);

        assertEquals(200, status);
        verify(authService, times(1)).invalidateToken();
        verify(pendientes, never()).save(any());

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient, times(2)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals("Bearer token-caducado", captor.getAllValues().get(0).headers().firstValue("Authorization").orElse(""));
        assertEquals("Bearer token-renovado", captor.getAllValues().get(1).headers().firstValue("Authorization").orElse(""));
    }

    @Test
    @SuppressWarnings("unchecked")
    void anteDoble401GuardaEventoEnColaSinBucleInfinito() throws Exception {
        when(pendientes.count()).thenReturn(0L);
        when(authService.getToken()).thenReturn("token-1", "token-2");

        HttpResponse<String> res401 = mockResponse(401, "{\"error\":\"unauthorized\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(res401, res401);

        int status = senderService.enviarEvento(SAMPLE_EVENT, 12L);

        assertEquals(401, status);
        verify(authService, times(1)).invalidateToken();
        verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        verify(pendientes, times(1)).save(any(EventoPendiente.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void ante503GuardaEnColaConservandoMismoJson() throws Exception {
        when(pendientes.count()).thenReturn(0L);
        when(authService.getToken()).thenReturn("token-valido");

        HttpResponse<String> res503 = mockResponse(503, "{\"error\":\"STORAGE_UNAVAILABLE\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(res503);

        int status = senderService.enviarEvento(SAMPLE_EVENT, 13L);

        assertEquals(503, status);
        ArgumentCaptor<EventoPendiente> captor = ArgumentCaptor.forClass(EventoPendiente.class);
        verify(pendientes, times(1)).save(captor.capture());
        assertEquals(SAMPLE_EVENT, captor.getValue().getJson());
        assertEquals(13L, captor.getValue().getAttemptId());
    }

    @Test
    @SuppressWarnings("unchecked")
    void anteTimeoutGuardaEnColaConservandoMismoJson() throws Exception {
        when(pendientes.count()).thenReturn(0L);
        when(authService.getToken()).thenReturn("token-valido");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new HttpTimeoutException("request timed out"));

        int status = senderService.enviarEvento(SAMPLE_EVENT, 16L);

        assertEquals(-1, status);
        ArgumentCaptor<EventoPendiente> captor = ArgumentCaptor.forClass(EventoPendiente.class);
        verify(pendientes, times(1)).save(captor.capture());
        assertEquals(SAMPLE_EVENT, captor.getValue().getJson());
        assertEquals(16L, captor.getValue().getAttemptId());
    }

    @Test
    @SuppressWarnings("unchecked")
    void ante409ConsideraRechazoDefinitivoYNoEncola() throws Exception {
        when(pendientes.count()).thenReturn(0L);
        when(authService.getToken()).thenReturn("token-valido");

        HttpResponse<String> res409 = mockResponse(409, "{\"error\":\"EVENT_ID_CONFLICT\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(res409);

        int status = senderService.enviarEvento(SAMPLE_EVENT, 14L);

        assertEquals(409, status);
        verify(pendientes, never()).save(any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void reintentoDesdeColaDescartaEventoAnte409Conflict() throws Exception {
        LoginAttemptRepository loginRepo = mock(LoginAttemptRepository.class);
        ReintentoSiemService reintentoService = new ReintentoSiemService(pendientes, loginRepo, senderService);

        EventoPendiente pendiente = new EventoPendiente(SAMPLE_EVENT, 17L);
        when(pendientes.findTop100ByOrderByIdAsc()).thenReturn(List.of(pendiente));
        when(authService.getToken()).thenReturn("token-cola");

        HttpResponse<String> res409 = mockResponse(409, "{\"error\":\"EVENT_ID_CONFLICT\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(res409);

        int enviados = reintentoService.reintentarPendientes();

        assertEquals(0, enviados);
        verify(pendientes, times(1)).delete(pendiente);
        verify(loginRepo, never()).findById(any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void reintentoDesdeColaUsaAutenticacionBearer() throws Exception {
        LoginAttemptRepository loginRepo = mock(LoginAttemptRepository.class);
        ReintentoSiemService reintentoService = new ReintentoSiemService(pendientes, loginRepo, senderService);

        EventoPendiente pendiente = new EventoPendiente(SAMPLE_EVENT, null);
        when(pendientes.findTop100ByOrderByIdAsc()).thenReturn(List.of(pendiente));
        when(authService.getToken()).thenReturn("token-cola");

        HttpResponse<String> res200 = mockResponse(200, "{\"status\":\"accepted\",\"event_id\":\"hp-evt-001\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(res200);

        int enviados = reintentoService.reintentarPendientes();

        assertEquals(1, enviados);
        verify(pendientes, times(1)).delete(pendiente);

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient, times(1)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals("Bearer token-cola", captor.getValue().headers().firstValue("Authorization").orElse(""));
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<String> mockResponse(int status, String body) {
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body);
        return response;
    }
}
