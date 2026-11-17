package com.honeypot.honeypot.service;

import com.honeypot.honeypot.model.EventoPendiente;
import com.honeypot.honeypot.repository.EventoPendienteRepository;
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

    private final EventoPendienteRepository pendientes;

    public SiemSenderService(EventoPendienteRepository pendientes) {
        this.pendientes = pendientes;
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
     * Envía el JSON del evento al SIEM mediante una petición HTTP POST, sin pasar por la cola.
     *
     * @param jsonPayload Cadena JSON válida correspondiente al evento.
     * @return Código de respuesta HTTP o -1 si no se pudo conectar.
     */
    public int enviarSinCola(String jsonPayload) {
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

    public static boolean esExito(int statusCode) {
        return statusCode == 200 || statusCode == 201;
    }

    // Solo se reintenta si el SIEM no responde o falla él. Los 4xx no se arreglan reenviando,
    // y con 507 el SIEM ya ha guardado el evento (contrato con el grupo 5)
    public static boolean hayQueReintentar(int statusCode) {
        return statusCode == -1 || (statusCode >= 500 && statusCode != 507);
    }

    private void guardarPendiente(String jsonPayload, Long attemptId) {
        pendientes.save(new EventoPendiente(jsonPayload, attemptId));
        log.info("Evento guardado como pendiente hasta que el SIEM responda");
    }

    public String getSiemUrl() {
        return siemUrl;
    }
}
