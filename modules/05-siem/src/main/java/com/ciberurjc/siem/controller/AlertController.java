package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.models.Alert;
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
    public ResponseEntity<Alert> getAlertById(@PathVariable String id) {
        return alertService.getAlertById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}