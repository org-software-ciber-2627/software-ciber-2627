package com.ciberurjc.siem.services;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Alert store shared by ingestion and the GET /alerts endpoints (SEM-121 / HU23).
 * Implementations must keep one alert per (source, event_id) and never replace a stored alert.
 */
public interface AlertRepository {

    enum SaveResult { CREATED, UNCHANGED }

    /**
     * Stores the alert unless its event already has one. An existing alert is kept as stored,
     * even if the current converter would produce different fields.
     */
    SaveResult insertIfAbsent(Map<String, Object> alert);

    List<Map<String, Object>> findAll();

    Optional<Map<String, Object>> findById(String alertId);
}
