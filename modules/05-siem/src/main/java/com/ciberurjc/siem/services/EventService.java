package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Event;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.time.format.DateTimeParseException;

@Service
public class EventService {
    private static final Logger logger = LoggerFactory.getLogger(EventService.class);

    public void processIncomingEvent(Event event) {
        try {
            if (!event.timestamp().endsWith("Z")) {
                throw new IllegalArgumentException("Timestamp must use UTC with a Z suffix");
            }
            Instant.parse(event.timestamp());
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException("Timestamp must be a valid UTC date-time", exception);
        }
        logger.info("Mock event received: id={}, source={}", event.event_id(), event.source());
    }
}
