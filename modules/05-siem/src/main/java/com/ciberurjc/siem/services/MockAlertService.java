package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Alert;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Service
public class MockAlertService {
    private final List<Alert> mockAlerts;

    public MockAlertService(ObjectMapper mapper) throws IOException {
        try (var input = new ClassPathResource("mocks/alerts.json").getInputStream()) {
            mockAlerts = List.copyOf(mapper.readValue(input, AlertFixtures.class).alerts());
        }
    }

    public List<Alert> getAllAlerts() {
        return mockAlerts;
    }

    public Optional<Alert> getAlertById(String id) {
        return mockAlerts.stream().filter(alert -> alert.alert_id().equals(id)).findFirst();
    }

    public record AlertFixtures(List<Alert> alerts) {}
}
