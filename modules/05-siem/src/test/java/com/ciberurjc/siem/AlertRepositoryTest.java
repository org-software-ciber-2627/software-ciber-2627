
package com.ciberurjc.siem;

import com.ciberurjc.siem.services.AlertConflictException;
import com.ciberurjc.siem.services.AlertRepository;
import com.ciberurjc.siem.services.AlertStorageFullException;
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

    @Test
    void identicalRetryIsUnchangedAndChangedContentIsRejected() {

        AlertRepository repository = new AlertRepository();
        Map<String, Object> original = Map.of("alert_id", "SIEM-ALERT-001", "severity", "critical");

        assertEquals(AlertRepository.SaveResult.CREATED, repository.save(original));
        assertEquals(AlertRepository.SaveResult.UNCHANGED, repository.save(new java.util.LinkedHashMap<>(original)));

        assertThrows(AlertConflictException.class,
            () -> repository.save(Map.of("alert_id", "SIEM-ALERT-001", "severity", "low")));

        // La alerta original no se sustituye
        assertEquals("critical", repository.findById("SIEM-ALERT-001").orElseThrow().get("severity"));
    }

    @Test
    void rejectsNewAlertsWhenFullButAcceptsIdenticalRetries() {

        AlertRepository repository = new AlertRepository(2);
        Map<String, Object> first = Map.of("alert_id", "A-1");

        repository.save(first);
        repository.save(Map.of("alert_id", "A-2"));

        assertThrows(AlertStorageFullException.class, () -> repository.save(Map.of("alert_id", "A-3")));
        assertEquals(AlertRepository.SaveResult.UNCHANGED, repository.save(first));
        assertEquals(2, repository.findAll().size());
    }

    @Test
    void rejectsInvalidCapacity() {
        assertThrows(IllegalArgumentException.class, () -> new AlertRepository(0));
    }

    @Test
    @SuppressWarnings("unchecked")
    void nestedDetailsCannotBeMutatedFromOutside() {

        AlertRepository repository = new AlertRepository();
        Map<String, Object> details = new java.util.LinkedHashMap<>();
        details.put("ports", new java.util.ArrayList<>(java.util.List.of(22)));
        Map<String, Object> alert = new java.util.LinkedHashMap<>();
        alert.put("alert_id", "SIEM-ALERT-001");
        alert.put("details", details);

        repository.save(alert);
        details.put("injected", true);

        var stored = repository.findById("SIEM-ALERT-001").orElseThrow();
        ((Map<String, Object>) stored.get("details")).put("injected", true);
        ((java.util.List<Object>) ((Map<String, Object>) repository.findAll().get(0).get("details")).get("ports")).add(80);

        var reread = (Map<String, Object>) repository.findById("SIEM-ALERT-001").orElseThrow().get("details");
        assertEquals(Map.of("ports", java.util.List.of(22)), reread);
    }
}
