package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.repositories.AlertRepository;
import com.ciberurjc.siem.services.MockAlertService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/alerts")
public class AlertController {
    private final MockAlertService mockAlertService;
    private final ObjectProvider<AlertRepository> alertRepository;

    public AlertController(MockAlertService mockAlertService, ObjectProvider<AlertRepository> alertRepository) {
        this.mockAlertService = mockAlertService;
        this.alertRepository = alertRepository;
    }

    @GetMapping
    public Map<String, Object> getAllAlerts() {
        return Map.of("alerts", mockAlertService.getAllAlerts());
    }

    // HU17 / SEM-33: el detalle se lee de las alertas almacenadas, no del mock.
    @GetMapping("/{id}")
    public ResponseEntity<?> getAlertById(@PathVariable String id) {
        AlertRepository repository = alertRepository.getIfAvailable();
        if (repository == null) {
            return storageUnavailable();
        }
        try {
            var alert = repository.findById(id);
            if (alert.isPresent()) {
                return ResponseEntity.ok(alert.get());
            }
            return ResponseEntity.status(404).body(Map.of("error", Map.of(
                    "code", "ALERT_NOT_FOUND", "message", "The requested alert does not exist")));
        } catch (RuntimeException exception) {
            return storageUnavailable();
        }
    }

    private ResponseEntity<?> storageUnavailable() {
        return ResponseEntity.status(503).body(Map.of("error", Map.of(
                "code", "STORAGE_UNAVAILABLE", "message", "Alert storage is temporarily unavailable")));
    }
}