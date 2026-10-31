
package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Event;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class AlertConverter {

    public Map<String, Object> convert(Event event) {

        Map<String, Object> details = event.details();

        String sourceIp = null;
        String targetIp = null;

        switch (event.source()) {
            case "ids" -> {
                sourceIp = getString(details.get("source_ip"));
                targetIp = getString(details.get("target_ip"));
            }

            case "honeypot" -> {
                sourceIp = getString(details.get("source_ip"));
            }

            case "scanner" -> {
                Object target = details.get("target");

                if (target instanceof Map<?, ?> targetMap) {
                    targetIp = getString(targetMap.get("ip"));
                }
            }

            default -> throw new IllegalArgumentException(
                "Unknown event source"
            );
        }

        String alertId = "SIEM-ALERT-" +
            UUID.nameUUIDFromBytes(
                (event.source() + ":" + event.event_id())
                    .getBytes(StandardCharsets.UTF_8)
            );

        Map<String, Object> alert = new LinkedHashMap<>();

        alert.put("alert_id", alertId);
        alert.put("event_id", event.event_id());
        alert.put("timestamp", event.timestamp());
        alert.put("source", event.source());
        alert.put("event_type", event.event_type());
        alert.put("severity", event.severity());
        alert.put("title", event.title());
        alert.put("description", event.description());
        alert.put("source_ip", sourceIp);
        alert.put("target_ip", targetIp);
        alert.put("details", details);

        return alert;
    }

    private String getString(Object value) {
        return value instanceof String text ? text : null;
    }
}

