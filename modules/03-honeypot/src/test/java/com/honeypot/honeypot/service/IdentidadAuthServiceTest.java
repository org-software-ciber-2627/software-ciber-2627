package com.honeypot.honeypot.service;

import com.honeypot.honeypot.config.IdentidadProperties;
import com.honeypot.honeypot.service.IdentidadAuthService.IdentidadAuthException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class IdentidadAuthServiceTest {

    private HttpClient httpClient;
    private MutableClock clock;
    private IdentidadProperties properties;
    private IdentidadAuthService authService;

    @BeforeEach
    void setUp() {
        httpClient = mock(HttpClient.class);
        clock = new MutableClock(Instant.parse("2026-11-26T18:00:00Z"));
        properties = new IdentidadProperties("http://identidad:80", "svc-honeypot", "secreto-123", 120);
        authService = new IdentidadAuthService(properties, httpClient, clock);
    }

    @Test
    @SuppressWarnings("unchecked")
    void obtieneYReutilizaTokenMientrasSeaValidoSinEnviarXForwardedFor() throws Exception {
        HttpResponse<String> response = mockResponse(200, "{\"token\":\"jwt-inicial\"}", Map.of());
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(response);

        String token1 = authService.getToken();
        clock.advance(Duration.ofMinutes(15));
        String token2 = authService.getToken();

        assertEquals("jwt-inicial", token1);
        assertEquals("jwt-inicial", token2);

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient, times(1)).send(captor.capture(), any(HttpResponse.BodyHandler.class));

        HttpRequest sentRequest = captor.getValue();
        assertEquals("http://identidad:80/auth/login", sentRequest.uri().toString());
        assertTrue(sentRequest.headers().firstValue("X-Forwarded-For").isEmpty());
    }

    @Test
    @SuppressWarnings("unchecked")
    void renuevaTokenAntesDeCaducarLos30Minutos() throws Exception {
        HttpResponse<String> res1 = mockResponse(200, "{\"token\":\"jwt-1\"}", Map.of());
        HttpResponse<String> res2 = mockResponse(200, "{\"token\":\"jwt-2\"}", Map.of());
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(res1, res2);

        assertEquals("jwt-1", authService.getToken());

        // Con margen de 120s (2 min), a los 28m01s ya debe solicitar renovación
        clock.advance(Duration.ofMinutes(28).plusSeconds(1));
        assertEquals("jwt-2", authService.getToken());

        verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void invalidarTokenFuerzaNuevoLogin() throws Exception {
        HttpResponse<String> res1 = mockResponse(200, "{\"token\":\"jwt-1\"}", Map.of());
        HttpResponse<String> res2 = mockResponse(200, "{\"token\":\"jwt-nuevo\"}", Map.of());
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(res1, res2);

        assertEquals("jwt-1", authService.getToken());
        authService.invalidateToken();
        assertEquals("jwt-nuevo", authService.getToken());

        verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void respetaRetryAfterAnte429DeIdentidad() throws Exception {
        HttpResponse<String> res429 = mockResponse(429, "{\"error\":\"rate_limited\"}", Map.of("Retry-After", List.of("45")));
        HttpResponse<String> res200 = mockResponse(200, "{\"token\":\"jwt-recuperado\"}", Map.of());
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(res429, res200);

        // Primer intento recibe 429 con Retry-After: 45s
        assertThrows(IdentidadAuthException.class, () -> authService.getToken());

        // A los 20s sigue bloqueado sin hacer llamadas HTTP extra
        clock.advance(Duration.ofSeconds(20));
        assertThrows(IdentidadAuthException.class, () -> authService.getToken());
        verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));

        // Pasados los 45s vuelve a intentar y obtiene token
        clock.advance(Duration.ofSeconds(26));
        assertEquals("jwt-recuperado", authService.getToken());
        verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void usaBackoffPorDefectoDe60SegundosSi429NoTraeRetryAfter() throws Exception {
        HttpResponse<String> res429 = mockResponse(429, "{\"error\":\"rate_limited\"}", Map.of());
        HttpResponse<String> res200 = mockResponse(200, "{\"token\":\"jwt-tras-60s\"}", Map.of());
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(res429, res200);

        assertThrows(IdentidadAuthException.class, () -> authService.getToken());

        clock.advance(Duration.ofSeconds(59));
        assertThrows(IdentidadAuthException.class, () -> authService.getToken());
        verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));

        clock.advance(Duration.ofSeconds(2));
        assertEquals("jwt-tras-60s", authService.getToken());
        verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void fallaSiNoHayContrasenaConfigurada() {
        IdentidadProperties sinPass = new IdentidadProperties("http://identidad:80", "svc-honeypot", "", 120);
        IdentidadAuthService serviceSinPass = new IdentidadAuthService(sinPass, httpClient, clock);

        assertThrows(IdentidadAuthException.class, serviceSinPass::getToken);
        verifyNoInteractions(httpClient);
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<String> mockResponse(int status, String body, Map<String, List<String>> headers) {
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body);
        when(response.headers()).thenReturn(HttpHeaders.of(headers, (k, v) -> true));
        return response;
    }

    private static class MutableClock extends Clock {
        private Instant current;

        MutableClock(Instant initial) {
            this.current = initial;
        }

        void advance(Duration duration) {
            this.current = this.current.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return current;
        }
    }
}
