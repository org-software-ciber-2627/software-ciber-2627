package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.services.AlertConverter;
import com.ciberurjc.siem.services.AlertQueryService;
import com.ciberurjc.siem.services.AlertRepository;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AlertQueryServiceTest {
    @Test
    void returnsEmptyWhenStorageIsEmpty() {
        assertTrue(new AlertQueryService(new AlertRepository()).findAll().isEmpty());
    }

    @Test
    void returnsAllGeneratedFieldsIncludingNullAddresses() {
        var repository = new AlertRepository();
        var event = new Event("query-honeypot", "2026-11-03T12:00:00Z", "honeypot",
            "fuerza_bruta", "high", "SSH attempts", "Repeated SSH attempts",
            Map.of("source_ip", "192.0.2.10", "service", "ssh"));
        var generated = new AlertConverter().convert(event);
        repository.save(generated);

        var alerts = new AlertQueryService(repository).findAll();
        assertEquals(1, alerts.size());
        assertEquals(generated, alerts.get(0));
        assertEquals(Set.of("alert_id", "event_id", "timestamp", "source", "event_type",
            "severity", "title", "description", "source_ip", "target_ip", "details"),
            alerts.get(0).keySet());
        assertNull(alerts.get(0).get("target_ip"));
    }

    @Test
    void readsCurrentStorageWithoutTruncationOrOrderAssumptions() {
        var repository = new AlertRepository();
        var query = new AlertQueryService(repository);
        assertTrue(query.findAll().isEmpty());
        var converter = new AlertConverter();
        for (int i = 0; i < 150; i++) {
            repository.save(converter.convert(new Event("query-" + i,
                "2026-11-03T12:00:00Z", "scanner", "finding", "low", "Finding",
                "Scanner finding", Map.of("target", Map.of("ip", "192.0.2.20")))));
        }
        var alerts = query.findAll();
        assertEquals(150, alerts.size());
        assertEquals(repository.findAll().stream().map(a -> a.get("alert_id")).collect(Collectors.toSet()),
            alerts.stream().map(a -> a.get("alert_id")).collect(Collectors.toSet()));
    }

    @Test
    void doesNotHideRepositoryFailureAsAnEmptyList() {
        var repository = mock(AlertRepository.class);
        var failure = new IllegalStateException("Storage read failed");
        when(repository.findAll()).thenThrow(failure);
        assertSame(failure, assertThrows(IllegalStateException.class,
            () -> new AlertQueryService(repository).findAll()));
    }
}
