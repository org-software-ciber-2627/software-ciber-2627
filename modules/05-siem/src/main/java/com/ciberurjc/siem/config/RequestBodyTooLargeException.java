package com.ciberurjc.siem.config;

import java.io.IOException;

public class RequestBodyTooLargeException extends IOException {
    public RequestBodyTooLargeException() {
        super("Request body exceeds the maximum allowed size");
    }
}
