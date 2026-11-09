package com.ciberurjc.siem.services;

public class EventStorageUnavailableException extends RuntimeException {
    public EventStorageUnavailableException() {
        super("Event storage is temporarily unavailable");
    }
}
