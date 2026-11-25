
package com.ciberurjc.siem.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public class AlertRepository {

    public static final int DEFAULT_MAX_ALERTS = 10_000;

    public enum SaveResult { CREATED, UNCHANGED }

    private final Map<String, Map<String, Object>> alerts =
        new LinkedHashMap<>();

    private final int maxAlerts;

    public AlertRepository() {
        this(DEFAULT_MAX_ALERTS);
    }

    @Autowired
    public AlertRepository(@Value("${siem.alerts.max-stored:" + DEFAULT_MAX_ALERTS + "}") int maxAlerts) {
        if (maxAlerts < 1) {
            throw new IllegalArgumentException("siem.alerts.max-stored must be at least 1");
        }
        this.maxAlerts = maxAlerts;
    }

    /**
     * Stores a new alert. A retry with identical content is accepted without
     * changes; different content for an existing alert_id is rejected so a
     * stored alert can never be silently replaced.
     */
    public SaveResult save(Map<String, Object> alert) {
        return save(alert, false);
    }

    public synchronized SaveResult save(Map<String, Object> alert, boolean confirmedReplay) {
        String id = (String) alert.get("alert_id");
        Map<String, Object> existing = alerts.get(id);

        if (existing != null) {
            if (confirmedReplay || existing.equals(alert)) {
                return SaveResult.UNCHANGED;
            }
            throw new AlertConflictException(id);
        }

        if (alerts.size() >= maxAlerts) {
            throw new AlertStorageFullException();
        }

        alerts.put(id, copyAlert(alert));
        return SaveResult.CREATED;
    }

    public synchronized List<Map<String, Object>> findAll() {
        return alerts.values()
            .stream()
            .map(AlertRepository::copyAlert)
            .toList();
    }

    public synchronized Optional<Map<String, Object>> findById(String id) {
        Map<String, Object> alert = alerts.get(id);

        if (alert == null) {
            return Optional.empty();
        }

        return Optional.of(copyAlert(alert));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> copyAlert(Map<String, Object> alert) {
        return (Map<String, Object>) deepCopy(alert);
    }

    // Nested details must not be shared with callers, otherwise stored alerts could be mutated.
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
