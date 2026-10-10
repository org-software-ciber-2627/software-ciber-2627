package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Alert;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class MockAlertService {

    private final List<Alert> mockAlerts = List.of(
        new Alert(
            "SIEM-ALERT-EJEMPLO-001", "IDS-EJEMPLO-001", "2026-09-22T18:30:15Z", 
            "ids", "port_scan", "medium", "Posible escaneo de puertos", 
            "Una IP ha contactado con 20 puertos del mismo destino en 60 segundos.", 
            "192.168.1.50", "192.168.1.10", 
            Map.of("rule_id", "IDS-001", "protocol", "tcp")
        ),
        new Alert(
            "SIEM-ALERT-EJEMPLO-002", "HP-981839239323", "2026-09-22T18:30:15Z", 
            "honeypot", "fuerza_bruta", "medium", "Intento de fuerza bruta en el honeypot", 
            "El honeypot ha registrado un evento clasificado como fuerza bruta sobre SSH.", 
            "192.168.1.50", null, 
            Map.of("service", "ssh", "username", "root")
        )
    );

    public List<Alert> getAllAlerts() {
        return mockAlerts;
    }

    public Optional<Alert> getAlertById(String id) {
        return mockAlerts.stream()
                .filter(a -> a.alert_id().equalsIgnoreCase(id))
                .findFirst();
    }
}