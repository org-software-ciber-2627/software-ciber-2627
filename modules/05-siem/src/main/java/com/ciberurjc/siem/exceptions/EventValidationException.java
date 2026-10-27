package com.ciberurjc.siem.exceptions;

/** A validation failure with a client-safe field name and reason, never the submitted value. */
public class EventValidationException extends RuntimeException {
    public EventValidationException(String field, String reason) {
        super(field + ": " + reason);
    }

    public EventValidationException(String field, String reason, Throwable cause) {
        super(field + ": " + reason, cause);
    }
}
