package com.ciberurjc.siem.models;

import java.util.Map;

public record Alert(
    String alert_id,
    String event_id,
    String timestamp,
    String source,
    String event_type,
    String severity,
    String title,
    String description,
    String source_ip,
    String target_ip,
    Map<String, Object> details
) {}