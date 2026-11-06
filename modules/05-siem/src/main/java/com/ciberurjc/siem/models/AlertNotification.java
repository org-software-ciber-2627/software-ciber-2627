
package com.ciberurjc.siem.models;

import java.util.Map;

public record AlertNotification(
    Map<String, Object> alert
) {}

