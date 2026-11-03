package com.ciberurjc.siem.models;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.Map;

public record Event(
    @NotBlank(message = "is required and must not be blank")
    @Pattern(regexp = "[A-Za-z0-9._:-]{1,128}",
        message = "must contain 1 to 128 ASCII letters, digits, dots, underscores, colons or hyphens") String event_id,
    @NotBlank(message = "is required and must not be blank") String timestamp,
    @NotNull(message = "is required")
    @Pattern(regexp = "ids|honeypot|scanner", message = "must be one of: ids, honeypot, scanner") String source,
    @NotBlank(message = "is required and must not be blank") String event_type,
    @NotNull(message = "is required")
    @Pattern(regexp = "low|medium|high|critical", message = "must be one of: low, medium, high, critical") String severity,
    @NotBlank(message = "is required and must not be blank") String title,
    @NotBlank(message = "is required and must not be blank") String description,
    @NotNull(message = "is required and must be a JSON object") Map<String, Object> details
) {}
