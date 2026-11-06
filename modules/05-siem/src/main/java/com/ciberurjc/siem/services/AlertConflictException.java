package com.ciberurjc.siem.services;

public class AlertConflictException extends RuntimeException {
    private final String alertId;

    public AlertConflictException(String alertId) {
        super("Alert already stored with different content");
        this.alertId = alertId;
    }

    public String alertId() {
        return alertId;
    }
}
