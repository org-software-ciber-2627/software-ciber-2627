package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.services.AlertRepository;
import com.ciberurjc.siem.services.AlertQueryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/alerts")
public class AlertController {
    private final AlertQueryService alertQueryService;
    private final AlertRepository alertRepository;

    public AlertController(AlertQueryService alertQueryService, AlertRepository alertRepository) {
        this.alertQueryService = alertQueryService;
        this.alertRepository = alertRepository;
    }

    @GetMapping
    public Map<String, Object> getAllAlerts() {
        return Map.of("alerts", alertQueryService.findAll());
    }

    // HU17 / SEM-33: el detalle se lee del almacén común de alertas (HU13).
    @GetMapping("/{id}")
    public ResponseEntity<?> getAlertById(@PathVariable String id) {
        var alert = alertRepository.findById(id);
        if (alert.isPresent()) {
            return ResponseEntity.ok(alert.get());
        }
        return ResponseEntity.status(404).body(Map.of("error", Map.of(
                "code", "ALERT_NOT_FOUND", "message", "The requested alert does not exist")));
    }
}