package com.ciberurjc.siem.services;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Without the persistence profile there is no alert store: reads report 503 instead of an
 * empty list that would look like a successful query (SEM-146, decision D6).
 */
@Repository
@Profile("!persistence")
public class UnavailableAlertRepository implements AlertRepository {

    @Override
    public SaveResult insertIfAbsent(Map<String, Object> alert) {
        throw new AlertStorageUnavailableException(null);
    }

    @Override
    public List<Map<String, Object>> findAll() {
        throw new AlertStorageUnavailableException(null);
    }

    @Override
    public Optional<Map<String, Object>> findById(String alertId) {
        throw new AlertStorageUnavailableException(null);
    }
}
