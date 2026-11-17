package com.ciberurjc.siem.services;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class AlertQueryService {
    private final AlertRepository repository;

    public AlertQueryService(AlertRepository repository) {
        this.repository = repository;
    }

    public List<Map<String, Object>> findAll() {
        return repository.findAll();
    }
}
