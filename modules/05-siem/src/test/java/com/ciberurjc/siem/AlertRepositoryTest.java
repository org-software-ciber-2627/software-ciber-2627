
package com.ciberurjc.siem;

import com.ciberurjc.siem.services.AlertRepository;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AlertRepositoryTest {

    @Test
    void shouldSaveAndRetrieveAlert() {

        AlertRepository repository = new AlertRepository();

        Map<String, Object> alert = Map.of(
            "alert_id", "SIEM-ALERT-001",
            "event_id", "IDS-001",
            "severity", "high"
        );

        // Guardar la alerta
        repository.save(alert);

        // Comprobar que aparece en el listado
        assertEquals(1, repository.findAll().size());

        // Comprobar que podemos buscarla por su ID
        var savedAlert = repository.findById("SIEM-ALERT-001");

        assertTrue(savedAlert.isPresent());
        assertEquals("IDS-001", savedAlert.get().get("event_id"));
        assertEquals("high", savedAlert.get().get("severity"));
    }

    @Test
    void shouldNotDuplicateAlerts() {

        AlertRepository repository = new AlertRepository();

        Map<String, Object> alert = Map.of(
            "alert_id", "SIEM-ALERT-001",
            "severity", "high"
        );

        repository.save(alert);
        repository.save(alert);

        assertEquals(1, repository.findAll().size());
    }

    @Test
    void shouldReturnEmptyForUnknownAlert() {

        AlertRepository repository = new AlertRepository();

        assertTrue(repository.findById("UNKNOWN").isEmpty());
    }
}

