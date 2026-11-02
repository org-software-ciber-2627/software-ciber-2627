
package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Event;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;

@Service
public class EventService {

    private static final Logger logger =
        LoggerFactory.getLogger(EventService.class);

    private final AlertConverter alertConverter;
    private final AlertService alertService;
    private final AlertRepository alertRepository;

    public EventService(
            AlertConverter alertConverter,
            AlertService alertService,
            AlertRepository alertRepository) {

        this.alertConverter = alertConverter;
        this.alertService = alertService;
        this.alertRepository = alertRepository;
    }

    public void processIncomingEvent(Event event) {

        try {
            if (!event.timestamp().endsWith("Z")) {
                throw new IllegalArgumentException(
                    "Timestamp must use UTC with a Z suffix"
                );
            }

            Instant.parse(event.timestamp());

        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                "Timestamp must be a valid UTC date-time",
                exception
            );
        }

        // 1. Convertir el evento en una alerta
        Map<String, Object> alert =
            alertConverter.convert(event);

        // 2. Guardar la alerta
        alertRepository.save(alert);

        // 3. Emitir la notificacion
        alertService.emitAlert(alert);

        logger.info(
            "Event processed and alert stored: event_id={}, alert_id={}",
            event.event_id(),
            alert.get("alert_id")
        );
    }
}
