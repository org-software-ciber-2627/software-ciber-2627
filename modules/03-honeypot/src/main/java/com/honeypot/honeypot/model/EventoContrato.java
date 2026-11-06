package com.honeypot.honeypot.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public record EventoContrato(
    @JsonProperty("event_id") String eventId,
    String timestamp,
    String source,
    @JsonProperty("event_type") String eventType,
    String severity,
    String title,
    String description,
    Map<String, Object> details
) {}