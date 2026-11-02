
package com.ciberurjc.siem.services;

import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public class AlertRepository {

    private final Map<String, Map<String, Object>> alerts =
        new LinkedHashMap<>();

    public synchronized void save(Map<String, Object> alert) {
        String id = (String) alert.get("alert_id");
        alerts.put(id, new LinkedHashMap<>(alert));
    }

    public synchronized List<Map<String, Object>> findAll() {
        return alerts.values()
            .stream()
            .map(LinkedHashMap::new)
            .map(alert -> (Map<String, Object>) alert)
            .toList();
    }

    public synchronized Optional<Map<String, Object>> findById(String id) {
        Map<String, Object> alert = alerts.get(id);

        if (alert == null) {
            return Optional.empty();
        }

        return Optional.of(new LinkedHashMap<>(alert));
    }
}
