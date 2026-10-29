package com.ciberurjc.siem.services;

public class InvalidHistoryQueryException extends RuntimeException {
    public InvalidHistoryQueryException() {
        super("Invalid history query parameters");
    }
}
