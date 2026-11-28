package com.honeypot.honeypot.service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.honeypot.honeypot.model.EventoPendiente;
import com.honeypot.honeypot.repository.EventoPendienteRepository;
import com.honeypot.honeypot.service.IdentidadAuthService.IdentidadAuthException;

@Service
public class SiemSenderService {

    private static final Logger log = LoggerFactory.getLogger(SiemSenderService.class);
    private static final Pattern EVENT_ID_PATTERN = Pattern.compile("\"event_id\"\\s*:\\s*\"([^\"]+)\"");

    // Lee la variable de entorno SIEM_URL; si no está definida, apunta al mock local
    @Value("${SIEM_URL:http://localhost:8081/events}")
    private String siemUrl;

    private final HttpClient httpClient;
    private final EventoPendienteRepository pendientes;
    private final IdentidadAuthService identidadAuthService;

    @Autowired
    public SiemSenderService(EventoPendienteRepository pendientes,
                             IdentidadAuthService identidadAuthService) {
        this(
                pendientes,
                identidadAuthService,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build()
        );
    }

    // Constructor de compatibilidad para tests existentes sin servidor de Identidad
    public SiemSenderService(EventoPendienteRepository pendientes) {
        this(pendientes, IdentidadAuthService.paraTests("test-token"));
    }

    // Constructor paquete-privado para inyectar HttpClient simulado en los tests unitarios
    SiemSenderService(EventoPendienteRepository pendientes,
                      IdentidadAuthService identidadAuthService,
                      HttpClient httpClient) {
        this.pendientes = pendientes;
        this.identidadAuthService = identidadAuthService;
        this.httpClient = httpClient;
    }

    // Constructor paquete-privado con URL explícita para tests unitarios
    SiemSenderService(EventoPendienteRepository pendientes,
                      IdentidadAuthService identidadAuthService,
                      HttpClient httpClient,
                      String siemUrl) {
        this(pendientes, identidadAuthService, httpClient);
        this.siemUrl = siemUrl;
    }

    /**
     * Envía el evento al SIEM. Si no se puede enviar, se guarda en la cola de pendientes (HP-22).
     * Si ya hay pendientes, el evento va detrás de ellos para que lleguen en orden.
     *
     * @param jsonPayload Cadena JSON válida correspondiente al evento.
     * @param attemptId Id del intento (o null), para marcarlo como enviado al reenviarlo.
     * @return Código de respuesta HTTP (ej. 200, 400, 503) o -1 si no se ha enviado.
     */
    public int enviarEvento(String jsonPayload, Long attemptId) {
        if (pendientes.count() > 0) {
            guardarPendiente(jsonPayload, attemptId);
            return -1;
        }

        int statusCode = enviarSinCola(jsonPayload);
        if (hayQueReintentar(statusCode)) {
            guardarPendiente(jsonPayload, attemptId);
        }
        return statusCode;
    }

    /**
     * Envía el JSON del evento al SIEM mediante una petición HTTP POST autenticada con Bearer token,
     * sin pasar por la cola. Ante 401 renueva el token una sola vez y reintenta el envío.
     *
     * @param jsonPayload Cadena JSON válida correspondiente al evento.
     * @return Código de respuesta HTTP o -1 si no se pudo conectar o validar el acuse.
     */
    public int enviarSinCola(String jsonPayload) {
        String token;
        try {
            token = identidadAuthService.getToken();
        } catch (IdentidadAuthException e) {
            log.warn("No se pudo obtener token de Identidad para enviar al SIEM: {}", e.getMessage());
            return -1;
        }

        try {
            HttpResponse<String> response = ejecutarPostSiem(jsonPayload, token);

            if (response.statusCode() == 401) {
                log.warn("El SIEM respondió 401 Unauthorized; renovando token con Identidad y reintentando una vez");
                identidadAuthService.invalidateToken();
                try {
                    token = identidadAuthService.getToken();
                } catch (IdentidadAuthException e) {
                    log.warn("No se pudo renovar el token tras 401 del SIEM: {}", e.getMessage());
                    return -1;
                }
                response = ejecutarPostSiem(jsonPayload, token);
            }

            int statusCode = response.statusCode();
            if (esExito(statusCode) && !acuseValido(jsonPayload, response.body())) {
                return -1;
            }

            return statusCode;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Envío al SIEM interrumpido");
            return -1;
        } catch (Exception e) {
            // Si el SIEM está caído o da timeout, la aplicación continúa sin romper el login
            log.warn("No se pudo conectar con el SIEM en {}: {}", siemUrl, e.getMessage());
            return -1;
        }
    }

    private HttpResponse<String> ejecutarPostSiem(String jsonPayload, String token)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(siemUrl))
                .timeout(Duration.ofSeconds(3))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();

        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private boolean acuseValido(String sentJson, String responseBody) {
        String sentEventId = extractEventId(sentJson);
        if (sentEventId == null || responseBody == null || responseBody.isBlank()) {
            return true;
        }
        String ackEventId = extractEventId(responseBody);
        if (!sentEventId.equals(ackEventId)) {
            log.warn("El acuse del SIEM no devuelve el mismo event_id enviado (esperado={}, recibido={})",
                    sentEventId, ackEventId);
            return false;
        }
        return true;
    }

    private static String extractEventId(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        Matcher matcher = EVENT_ID_PATTERN.matcher(json);
        if (matcher.find()) {
            String id = matcher.group(1).trim();
            return id.isEmpty() ? null : id;
        }
        return null;
    }

    public static boolean esExito(int statusCode) {
        return statusCode == 200 || statusCode == 201;
    }

    // Se reintenta si el SIEM no responde, falla él (excepto 507) o rechaza el token tras renovarlo (401).
    // Los demás 4xx (400, 409...) son rechazos definitivos y con 507 el SIEM ya guardó el evento.
    public static boolean hayQueReintentar(int statusCode) {
        return statusCode == -1 || statusCode == 401 || (statusCode >= 500 && statusCode != 507);
    }

    private void guardarPendiente(String jsonPayload, Long attemptId) {
        pendientes.save(new EventoPendiente(jsonPayload, attemptId));
        log.info("Evento guardado como pendiente hasta que el SIEM responda");
    }

    public String getSiemUrl() {
        return siemUrl;
    }
}