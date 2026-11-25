package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.services.AlertConverter;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AlertConverterTest {
    private final AlertConverter converter = new AlertConverter();

    @Test
    void convertsPentestingFindingWithoutInventingAddresses() {
        Map<String, Object> details = Map.of("tool", "OWASP ZAP", "target", "http://juice-shop:3000",
            "instances", 15, "solution", "Restrict Access-Control-Allow-Origin");
        var event = new Event("pt-zap-0001", "2026-11-04T12:00:00Z", "pentesting", "vulnerability_detected",
            "medium", "Cross-Domain Misconfiguration", "CORS misconfiguration", details);

        var alert = converter.convert(event);

        assertEquals("pentesting", alert.get("source"));
        assertEquals("pt-zap-0001", alert.get("event_id"));
        assertNull(alert.get("source_ip"));
        assertNull(alert.get("target_ip"));
        assertEquals(details, alert.get("details"));
        assertEquals(11, alert.size());
    }

    @Test
    void pentestingAlertIdDiffersFromOtherSourcesWithSameEventId() {
        var pentesting = new Event("shared-1", "2026-11-04T12:00:00Z", "pentesting", "vulnerability_detected",
            "low", "Finding", "Finding", Map.of());
        var scanner = new Event("shared-1", "2026-11-04T12:00:00Z", "scanner", "vulnerability_detected",
            "low", "Finding", "Finding", Map.of());

        assertNotEquals(converter.convert(pentesting).get("alert_id"), converter.convert(scanner).get("alert_id"));
    }

    @Test
    void rejectsSourcesOutsideTheCatalog() {
        var unknown = new Event("x-1", "2026-11-04T12:00:00Z", "identity", "login", "low", "Login", "Login", Map.of());

        assertThrows(IllegalArgumentException.class, () -> converter.convert(unknown));
    }
}
