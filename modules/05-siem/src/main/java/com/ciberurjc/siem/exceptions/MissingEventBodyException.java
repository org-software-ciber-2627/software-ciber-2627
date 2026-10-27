package com.ciberurjc.siem.exceptions;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageNotReadableException;

/** Identifies a missing event body without depending on Spring's exception wording. */
public final class MissingEventBodyException extends HttpMessageNotReadableException {
    public MissingEventBodyException(HttpInputMessage inputMessage) {
        super("Missing event request body", inputMessage);
    }
}
