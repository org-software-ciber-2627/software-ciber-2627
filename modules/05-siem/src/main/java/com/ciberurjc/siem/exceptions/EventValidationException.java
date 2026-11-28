package com.ciberurjc.siem.exceptions;

/**
 * A controlled input rejection from event processing (including a future converter).
 * Use a public field name and a fixed, client-safe reason, never the submitted value
 * or an arbitrary exception message. Unexpected internal failures must keep their own type.
 */
public class EventValidationException extends RuntimeException {
    public EventValidationException(String field, String reason) {
        super(field + ": " + reason);
    }

    public EventValidationException(String field, String reason, Throwable cause) {
        super(field + ": " + reason, cause);
    }
}
