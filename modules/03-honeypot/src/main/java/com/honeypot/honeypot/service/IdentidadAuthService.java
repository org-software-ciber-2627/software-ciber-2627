package com.honeypot.honeypot.service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.honeypot.honeypot.config.IdentidadProperties;

@Service
public class IdentidadAuthService {

    private static final Logger log = LoggerFactory.getLogger(IdentidadAuthService.class);
    private static final Duration TOKEN_TTL = Duration.ofMinutes(30);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final long DEFAULT_RETRY_AFTER_SECONDS = 60L;
    private static final Pattern TOKEN_PATTERN = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"");

    private final IdentidadProperties properties;
    private final HttpClient httpClient;
    private final Clock clock;
    private final Object lock = new Object();

    private String cachedToken;
    private Instant tokenExpiresAt;
    private Instant rateLimitedUntil;

    @Autowired
    public IdentidadAuthService(IdentidadProperties properties) {
        this(
                properties,
                HttpClient.newBuilder().connectTimeout(REQUEST_TIMEOUT).build(),
                Clock.systemUTC()
        );
    }

    // Constructor paquete-privado para inyectar mocks de HttpClient y Clock en los tests unitarios
    IdentidadAuthService(
            IdentidadProperties properties,
            HttpClient httpClient,
            Clock clock) {
        this.properties = properties;
        this.httpClient = httpClient;
        this.clock = clock;
    }

    /**
     * Devuelve un token JWT válido en memoria o solicita uno nuevo a Identidad
     * si no existe o está próximo a caducar.
     */
    public String getToken() {
        if (properties.getServicePassword() == null || properties.getServicePassword().isBlank()) {
            throw new IdentidadAuthException("SERVICE_PASSWORD_HONEYPOT no está configurada");
        }

        synchronized (lock) {
            Instant now = clock.instant();

            if (isTokenValid(now)) {
                return cachedToken;
            }

            if (rateLimitedUntil != null && now.isBefore(rateLimitedUntil)) {
                throw new IdentidadAuthException(
                        "Identidad en espera por 429 Retry-After hasta " + rateLimitedUntil
                );
            }

            return requestNewToken(now);
        }
    }

    /**
     * Invalida el token en caché (por ejemplo, si el SIEM responde 401 Unauthorized)
     * para forzar un nuevo login en la siguiente llamada a getToken().
     */
    public void invalidateToken() {
        synchronized (lock) {
            this.cachedToken = null;
            this.tokenExpiresAt = null;
        }
    }

    private boolean isTokenValid(Instant now) {
        if (cachedToken == null || tokenExpiresAt == null) {
            return false;
        }
        Instant refreshThreshold = tokenExpiresAt.minusSeconds(properties.getRefreshMarginSeconds());
        return now.isBefore(refreshThreshold);
    }

    private String requestNewToken(Instant now) {
        String baseUrl = properties.getUrl().replaceAll("/+$", "");
        URI loginUri = URI.create(baseUrl + "/auth/login");

        try {
            String payload = "{\"username\":\"" + escapeJson(properties.getServiceUser())
                    + "\",\"password\":\"" + escapeJson(properties.getServicePassword()) + "\"}";

            // Importante: no añadir cabecera X-Forwarded-For (requisito de seguridad de G1)
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(loginUri)
                    .timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();

            if (status == 429) {
                long retryAfterSeconds = parseRetryAfterSeconds(response);
                this.rateLimitedUntil = now.plusSeconds(retryAfterSeconds);
                log.warn("Identidad respondió 429 Too Many Requests. Esperando {}s antes de reintentar login.", retryAfterSeconds);
                throw new IdentidadAuthException("Identidad respondió 429 Too Many Requests (Retry-After: " + retryAfterSeconds + "s)");
            }

            if (status != 200) {
                log.warn("Fallo al autenticar {} en Identidad: HTTP {}", properties.getServiceUser(), status);
                throw new IdentidadAuthException("Error autenticando en Identidad: HTTP " + status);
            }

            String token = extractToken(response.body());
            if (token == null) {
                throw new IdentidadAuthException("Respuesta 200 de Identidad sin campo 'token' válido");
            }

            this.cachedToken = token;
            this.tokenExpiresAt = now.plus(TOKEN_TTL);
            this.rateLimitedUntil = null;

            log.info("Token JWT obtenido de Identidad para la cuenta {}", properties.getServiceUser());
            return this.cachedToken;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IdentidadAuthException("Interrupción al solicitar token a Identidad", e);
        } catch (IOException e) {
            throw new IdentidadAuthException("Error de red comunicando con Identidad", e);
        }
    }

    private static String extractToken(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        Matcher matcher = TOKEN_PATTERN.matcher(body);
        if (matcher.find()) {
            String token = matcher.group(1).trim();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    private long parseRetryAfterSeconds(HttpResponse<?> response) {
        return response.headers()
                .firstValue("Retry-After")
                .map(String::trim)
                .map(val -> {
                    try {
                        long seconds = Long.parseLong(val);
                        return Math.max(1L, seconds);
                    } catch (NumberFormatException ex) {
                        return DEFAULT_RETRY_AFTER_SECONDS;
                    }
                })
                .orElse(DEFAULT_RETRY_AFTER_SECONDS);
    }

    public static class IdentidadAuthException extends RuntimeException {
        public IdentidadAuthException(String message) {
            super(message);
        }

        public IdentidadAuthException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    static IdentidadAuthService paraTests(String fixedToken) {
        IdentidadProperties dummyProps = new IdentidadProperties("http://localhost:8081", "svc-honeypot", "dummy", 120);
        return new IdentidadAuthService(dummyProps, null, Clock.systemUTC()) {
            @Override
            public String getToken() {
                return fixedToken;
            }

            @Override
            public void invalidateToken() {
                // No-op en tests heredados
            }
        };
    }
}