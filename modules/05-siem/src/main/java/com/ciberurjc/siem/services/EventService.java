package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.exceptions.EventValidationException;
import com.ciberurjc.siem.repositories.EventRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.RecoverableDataAccessException;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionOperations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;

@Service
public class EventService {
    private static final Logger logger = LoggerFactory.getLogger(EventService.class);
    private final ObjectProvider<EventRepository> repositories;

    private final AlertRepository alerts;
    private final AlertConverter converter;
    private final AlertService alertService;
    private final RepeatedAuthenticationFailureEvaluator authenticationFailures;
    private final TransactionOperations transactions;

    @Autowired
    public EventService(ObjectProvider<EventRepository> repositories, AlertRepository alerts,
            AlertConverter converter, AlertService alertService,
            RepeatedAuthenticationFailureEvaluator authenticationFailures,
            ObjectProvider<TransactionOperations> transactions) {
        this(repositories, alerts, converter, alertService, authenticationFailures,
            transactions.getIfAvailable(TransactionOperations::withoutTransaction));
    }

    // Without the persistence profile (tests, in-memory stores) there is no transaction manager.
    public EventService(ObjectProvider<EventRepository> repositories, AlertRepository alerts,
            AlertConverter converter, AlertService alertService,
            RepeatedAuthenticationFailureEvaluator authenticationFailures,
            TransactionOperations transactions) {
        this.repositories = repositories;
        this.alerts = alerts;
        this.converter = converter;
        this.alertService = alertService;
        this.authenticationFailures = authenticationFailures;
        this.transactions = transactions;
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
        Outcome outcome;
        try {
            // Event and alert commit or roll back together (SEM-146 D3).
            outcome = transactions.execute(status -> store(repository, event));
        } catch (DataAccessResourceFailureException | TransientDataAccessException | RecoverableDataAccessException
                 | TransactionException exception) {
            // Availability problems: the producer may retry the same event (503).
            logger.warn("Event storage failed: id={}, source={}", logValue(event.event_id()), event.source());
            throw new EventStorageUnavailableException();
        } catch (DataAccessException exception) {
            // Schema or integrity errors need a fix, not a retry (500, SEM-146 D3). Type only, no payload.
            logger.error("Event storage error: id={}, source={}, error={}", logValue(event.event_id()), event.source(),
                exception.getClass().getName());
            throw new EventStorageFailureException();
        }
        logger.info("Event storage confirmed: id={}, source={}, result={}", logValue(event.event_id()), event.source(), outcome.result());
        if (outcome.createdAlert() != null) {
            notifyAfterCommit(outcome.createdAlert());
        }
    }

    private Outcome store(EventRepository repository, Event event) {
        EventRepository.SaveResult result = repository.saveIfAbsent(event);
        if (result == EventRepository.SaveResult.CONFLICT) {
            throw new EventIdConflictException();
        }
        if ("info".equals(event.severity())) {
            return new Outcome(result, null);
        }
        var alert = converter.convert(event);
        authenticationFailures.evaluate(event).ifPresent(
            detection -> alert.put("source_ip", detection.sourceIp().orElse(null)));
        // A replay creates the alert only if it is missing, e.g. for events stored before 005.
        boolean created = alerts.insertIfAbsent(alert) == AlertRepository.SaveResult.CREATED;
        return new Outcome(result, created ? alert : null);
    }

    // The write is already committed: a listener failure must not change the acknowledgement (SEM-146 D4).
    private void notifyAfterCommit(Map<String, Object> alert) {
        try {
            alertService.emitAlert(alert);
        } catch (RuntimeException exception) {
            // Exception type only: messages could carry alert content.
            logger.warn("Alert notification failed: alert_id={}, error={}", alert.get("alert_id"), exception.getClass().getName());
        }
    }

    private record Outcome(EventRepository.SaveResult result, Map<String, Object> createdAlert) {}

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
