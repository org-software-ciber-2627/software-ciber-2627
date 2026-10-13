package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.services.MockAlertService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/alerts")
public class AlertController {
    private final MockAlertService alertService;

    public AlertController(MockAlertService alertService) {
        this.alertService = alertService;
    }

    @GetMapping
    public Map<String, Object> getAllAlerts() {
        return Map.of("alerts", alertService.getAllAlerts());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getAlertById(@PathVariable String id) {
        var alert = alertService.getAlertById(id);
        if (alert.isPresent()) {
            return ResponseEntity.ok(alert.get());
        }
        return ResponseEntity.status(404).body(Map.of("error", Map.of(
                "code", "ALERT_NOT_FOUND", "message", "The requested alert does not exist")));
    }
}
