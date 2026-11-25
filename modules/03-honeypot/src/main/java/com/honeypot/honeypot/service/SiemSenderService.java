package com.honeypot.honeypot.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

@Service
public class SiemSenderService {

    private static final Logger log = LoggerFactory.getLogger(SiemSenderService.class);

    // Lee la variable de entorno SIEM_URL; si no está definida, apunta al mock local
    @Value("${SIEM_URL:http://localhost:8081/events}")
    private String siemUrl;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    /**
     * Envía el JSON del evento al SIEM mediante una petición HTTP POST.
     *
     * @param jsonPayload Cadena JSON válida correspondiente al evento.
     * @return Código de respuesta HTTP (ej. 201, 200, 422) o -1 si no se pudo conectar.
     */
    public int enviarEvento(String jsonPayload) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(siemUrl))
                    .timeout(Duration.ofSeconds(3))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode();

        } catch (Exception e) {
            // Si el SIEM está caído o da timeout, la aplicación continúa sin romper el login
            log.warn("No se pudo conectar con el SIEM en {}: {}", siemUrl, e.getMessage());
            return -1;
        }
    }

    public String getSiemUrl() {
        return siemUrl;
    }
}