package com.ciberurjc.siem.models;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.Map;

public record Event(
    @NotBlank String event_id,
    @NotBlank String timestamp,
    @NotNull @Pattern(regexp = "ids|honeypot|scanner") String source,
    @NotBlank String event_type,
    @NotNull @Pattern(regexp = "low|medium|high|critical") String severity,
    @NotBlank String title,
    @NotBlank String description,
    @NotNull Map<String, Object> details
) {}
