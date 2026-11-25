package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.exceptions.EventValidationException;
import com.ciberurjc.siem.repositories.EventRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.time.format.DateTimeParseException;

@Service
public class EventService {
    private static final Logger logger = LoggerFactory.getLogger(EventService.class);
    private final ObjectProvider<EventRepository> repositories;

    private final AlertRepository alerts;
    private final AlertConverter converter;
    private final AlertService alertService;
    private final RepeatedAuthenticationFailureEvaluator authenticationFailures;

    public EventService(ObjectProvider<EventRepository> repositories, AlertRepository alerts,
            AlertConverter converter, AlertService alertService,
            RepeatedAuthenticationFailureEvaluator authenticationFailures) {
        this.repositories = repositories;
        this.alerts = alerts;
        this.converter = converter;
        this.alertService = alertService;
        this.authenticationFailures = authenticationFailures;
    }

    public void processIncomingEvent(Event event) {
        try {
            if (!event.timestamp().endsWith("Z")) {
                throw new EventValidationException("timestamp", "must end with Z (UTC)");
            }
            Instant.parse(event.timestamp());
        } catch (DateTimeParseException exception) {
            throw new EventValidationException("timestamp", "must represent a valid UTC date-time", exception);
        }
        EventRepository repository = repositories.getIfAvailable();
        if (repository == null) {
            throw new EventStorageUnavailableException();
        }
        EventRepository.SaveResult result;
        try {
            result = repository.saveIfAbsent(event);
            if (result == EventRepository.SaveResult.CONFLICT) {
                throw new EventIdConflictException();
            }
            logger.info("Event storage confirmed: id={}, source={}, result={}", logValue(event.event_id()), event.source(), result);
        } catch (DataAccessException exception) {
            logger.warn("Event storage failed: id={}, source={}", logValue(event.event_id()), event.source());
            throw new EventStorageUnavailableException();
        }
        if ("info".equals(event.severity())) {
            return;
        }
        var alert = converter.convert(event);
        authenticationFailures.evaluate(event).ifPresent(
            detection -> alert.put("source_ip", detection.sourceIp().orElse(null)));
        if (alerts.save(alert, result == EventRepository.SaveResult.REPLAY) == AlertRepository.SaveResult.CREATED) {
            alertService.emitAlert(alert);
        }
    }

    private static String logValue(String value) {
        var safe = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            if (Character.isISOControl(character) || character == '\u2028' || character == '\u2029') {
                safe.append("\\u").append(String.format("%04x", (int) character));
            } else {
                safe.append(character);
            }
        }
        return safe.toString();
    }
}
