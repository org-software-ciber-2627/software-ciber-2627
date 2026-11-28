package com.ciberurjc.siem.services;

public class AlertStorageUnavailableException extends RuntimeException {
    public AlertStorageUnavailableException(Throwable cause) {
        super("Alert storage is temporarily unavailable", cause);
    }
}
