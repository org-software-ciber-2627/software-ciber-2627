package com.ciberurjc.siem.services;

public class EventIdConflictException extends RuntimeException {
    public EventIdConflictException() {
        super("The event identifier already belongs to different content");
    }
}
