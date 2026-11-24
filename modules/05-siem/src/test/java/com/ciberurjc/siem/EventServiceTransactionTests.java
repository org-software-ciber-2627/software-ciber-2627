package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.repositories.EventRepository;
import com.ciberurjc.siem.services.AlertConverter;
import com.ciberurjc.siem.services.AlertRepository;
import com.ciberurjc.siem.services.AlertService;
import com.ciberurjc.siem.services.EventIdConflictException;
import com.ciberurjc.siem.services.EventService;
import com.ciberurjc.siem.services.EventStorageUnavailableException;
import com.ciberurjc.siem.services.RepeatedAuthenticationFailureEvaluator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/** SEM-146 D3/D4: event and alert commit together; notifications only after a commit that created an alert. */
class EventServiceTransactionTests {
    final List<String> transactionLog = new ArrayList<>();
    final List<Object> notifications = new ArrayList<>();
    final InMemoryEvents events = new InMemoryEvents();
    final InMemoryAlertRepository alerts = new InMemoryAlertRepository();

    @Test
    void newEventCommitsItsAlertAndNotifiesOnce() {
        service(alerts, false).processIncomingEvent(event("tx-1", "high"));
        assertEquals(List.of("begin", "commit"), transactionLog);
        assertEquals(1, alerts.findAll().size());
        assertEquals(1, notifications.size());
    }

    @Test
    void alertFailureRollsBackTheEventAndReturns503() {
        AlertRepository failing = new InMemoryAlertRepository() {
            @Override
            public SaveResult insertIfAbsent(Map<String, Object> alert) {
                throw new DataAccessResourceFailureException("connection lost");
            }
        };
        assertThrows(EventStorageUnavailableException.class,
            () -> service(failing, false).processIncomingEvent(event("tx-2", "high")));
        assertEquals(List.of("begin", "rollback"), transactionLog);
        assertTrue(notifications.isEmpty());
    }

    @Test
    void transactionThatCannotStartReturns503() {
        var service = new EventService(provider(), alerts, new AlertConverter(),
            new AlertService(notifications::add), new RepeatedAuthenticationFailureEvaluator(),
            new TransactionTemplate(new RecordingTransactionManager(true)));
        assertThrows(EventStorageUnavailableException.class, () -> service.processIncomingEvent(event("tx-3", "high")));
        assertTrue(events.stored.isEmpty());
        assertTrue(alerts.findAll().isEmpty());
    }

    @Test
    void replayCompletesAMissingAlertOnlyOnce() {
        var stored = event("tx-4", "high");
        events.saveIfAbsent(stored); // stored before migration 005: no alert yet
        var service = service(alerts, false);
        service.processIncomingEvent(stored);
        service.processIncomingEvent(stored);
        assertEquals(1, alerts.findAll().size());
        assertEquals(1, notifications.size());
    }

    @Test
    void conflictingContentRollsBackWithoutTouchingAlerts() {
        var service = service(alerts, false);
        service.processIncomingEvent(event("tx-5", "high"));
        transactionLog.clear();
        assertThrows(EventIdConflictException.class, () -> service.processIncomingEvent(event("tx-5", "low")));
        assertEquals(List.of("begin", "rollback"), transactionLog);
        assertEquals("high", alerts.findAll().getFirst().get("severity"));
        assertEquals(1, notifications.size());
    }

    @Test
    void informationalEventsStoreNoAlert() {
        service(alerts, false).processIncomingEvent(event("tx-6", "info"));
        assertEquals(List.of("begin", "commit"), transactionLog);
        assertEquals(1, events.stored.size());
        assertTrue(alerts.findAll().isEmpty());
        assertTrue(notifications.isEmpty());
    }

    @Test
    void listenerFailureAfterCommitKeepsTheAcknowledgement() {
        assertDoesNotThrow(() -> service(alerts, true).processIncomingEvent(event("tx-7", "high")));
        assertEquals(List.of("begin", "commit"), transactionLog);
        assertEquals(1, alerts.findAll().size());
    }

    private EventService service(AlertRepository alertStore, boolean failingListener) {
        AlertService alertService = new AlertService(notification -> {
            if (failingListener) throw new IllegalStateException("listener failed");
            notifications.add(notification);
        });
        return new EventService(provider(), alertStore, new AlertConverter(), alertService,
            new RepeatedAuthenticationFailureEvaluator(), new TransactionTemplate(new RecordingTransactionManager(false)));
    }

    private org.springframework.beans.factory.ObjectProvider<EventRepository> provider() {
        var factory = new StaticListableBeanFactory();
        factory.addBean("events", events);
        return factory.getBeanProvider(EventRepository.class);
    }

    private static Event event(String id, String severity) {
        return new Event(id, "2026-11-24T12:00:00Z", "honeypot", "ssh_login_attempt", severity,
            "Login attempt", "Transaction test", Map.of("source_ip", "203.0.113.10"));
    }

    static class InMemoryEvents implements EventRepository {
        final Map<List<String>, Event> stored = new java.util.LinkedHashMap<>();

        public SaveResult saveIfAbsent(Event event) {
            var existing = stored.putIfAbsent(List.of(event.source(), event.event_id()), event);
            if (existing == null) return SaveResult.STORED;
            return existing.equals(event) ? SaveResult.REPLAY : SaveResult.CONFLICT;
        }

        public List<Event> findPage(int limit, long offset) { throw new UnsupportedOperationException(); }
        public void save(Event event) { throw new UnsupportedOperationException(); }
        public Optional<Event> findById(String source, String id) { throw new UnsupportedOperationException(); }
    }

    /** Records transaction boundaries; it cannot undo the in-memory stores, so tests assert the boundaries. */
    class RecordingTransactionManager extends AbstractPlatformTransactionManager {
        private final boolean failOnBegin;

        RecordingTransactionManager(boolean failOnBegin) {
            this.failOnBegin = failOnBegin;
        }

        @Override
        protected Object doGetTransaction() {
            return new Object();
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
            if (failOnBegin) throw new CannotCreateTransactionException("pool exhausted");
            transactionLog.add("begin");
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
            transactionLog.add("commit");
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
            transactionLog.add("rollback");
        }
    }
}
