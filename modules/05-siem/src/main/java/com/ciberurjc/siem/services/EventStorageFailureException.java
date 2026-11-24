package com.ciberurjc.siem.services;

/**
 * A storage error that retrying will not fix (schema or integrity), unlike
 * {@link EventStorageUnavailableException}. Mapped to 500 (SEM-146 D3).
 */
public class EventStorageFailureException extends RuntimeException {
    public EventStorageFailureException() {
        super("An unexpected error occurred");
    }
}
