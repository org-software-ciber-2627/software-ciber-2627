package com.ciberurjc.siem.services;

public class AlertStorageFullException extends RuntimeException {
    public AlertStorageFullException() {
        super("Alert storage has reached its capacity");
    }
}
