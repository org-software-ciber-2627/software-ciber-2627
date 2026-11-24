package com.ciberurjc.siem;

import com.ciberurjc.siem.services.AlertRepository;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Test-only alert store with the PostgreSQL semantics: one alert per event, never replaced. */
class InMemoryAlertRepository implements AlertRepository {
    private final Map<List<Object>, Map<String, Object>> alerts = new LinkedHashMap<>();

    @Override
    public synchronized SaveResult insertIfAbsent(Map<String, Object> alert) {
        var key = List.of(alert.get("source"), alert.get("event_id"));
        if (alerts.containsKey(key)) {
            return SaveResult.UNCHANGED;
        }
        alerts.put(key, copy(alert));
        return SaveResult.CREATED;
    }

    /** Seeds an alert directly, as an existing row would be. */
    void save(Map<String, Object> alert) {
        insertIfAbsent(alert);
    }

    @Override
    public synchronized List<Map<String, Object>> findAll() {
        return alerts.values().stream().map(InMemoryAlertRepository::copy).toList();
    }

    @Override
    public synchronized Optional<Map<String, Object>> findById(String alertId) {
        return alerts.values().stream().filter(alert -> alertId.equals(alert.get("alert_id")))
            .findFirst().map(InMemoryAlertRepository::copy);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> copy(Map<String, Object> alert) {
        return (Map<String, Object>) deepCopy(alert);
    }

    // Callers must not be able to mutate stored alerts through nested details.
    private static Object deepCopy(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            map.forEach((key, item) -> copy.put(String.valueOf(key), deepCopy(item)));
            return copy;
        }
        if (value instanceof List<?> list) {
            List<Object> copy = new ArrayList<>(list.size());
            list.forEach(item -> copy.add(deepCopy(item)));
            return copy;
        }
        return value;
    }
}
