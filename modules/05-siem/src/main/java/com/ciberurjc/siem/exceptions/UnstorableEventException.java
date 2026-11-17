package com.ciberurjc.siem.exceptions;

public class UnstorableEventException extends IllegalArgumentException {
    public UnstorableEventException(String message) {
        super(message);
    }

    public UnstorableEventException(String message, Throwable cause) {
        super(message, cause);
    }
}
