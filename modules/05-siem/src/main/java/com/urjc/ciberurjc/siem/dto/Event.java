package com.urjc.ciberurjc.siem.dto;
import java.util.List;
import java.util.Map;

public record Event(
    String event_id,          // UUID (Obligatorio)
    String timestamp,         // ISO 8601 (Obligatorio)
    String source_module,     // IDS|Honeypot|Scanner|SOAR|Dashboard (Obligatorio)
    String severity,          // low|medium|high|critical (Obligatorio)
    String event_type,        // string (Obligatorio)
    String source_ip,         // IPv4/IPv6 (Obligatorio)
    String destination_ip,    // IPv4/IPv6 (Opcional)
    String description,       // string (Obligatorio)
    Map<String, Object> raw_data, // object (Opcional)
    List<String> tags         // array[string] (Opcional)
) {}