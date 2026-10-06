package com.ciberurjc.siem.controllers;

import com.ciberurjc.siem.models.Alert;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/alerts")
public class AlertController {

    // Tus 3 alertas estáticas de prueba
    private final List<Alert> mockAlerts = List.of(
        new Alert("ALT-001", "2023-10-24T10:15:30Z", "Alta", "IDS", "Múltiples intentos de login fallidos", "192.168.1.45"),
        new Alert("ALT-002", "2023-10-24T11:05:12Z", "Media", "Escáner", "Puerto 3306 expuesto", "10.0.0.5"),
        new Alert("ALT-003", "2023-10-24T12:30:00Z", "Baja", "Honeypot", "Conexión FTP anónima", "203.0.113.10")
    );

    // Ruta principal que usarán el SOAR y el Dashboard
    @GetMapping
    public Map<String, Object> getAllAlerts() {
        return Map.of("alerts", mockAlerts);
    }

    // Ruta para buscar una alerta concreta por su ID
    @GetMapping("/{id}")
    public ResponseEntity<Alert> getAlertById(@PathVariable String id) {
        Optional<Alert> alert = mockAlerts.stream()
                .filter(a -> a.id().equalsIgnoreCase(id))
                .findFirst();

        return alert.map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}