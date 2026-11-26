package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.repositories.EventRepository;
import com.ciberurjc.siem.repositories.PostgresAlertRepository;
import com.ciberurjc.siem.services.AlertConverter;
import com.ciberurjc.siem.services.AlertRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("persistence")
@EnabledIfEnvironmentVariable(named = "SIEM_TEST_DB_URL", matches = ".+")
class PostgresAlertRepositoryTests {
    @Autowired AlertRepository alerts;
    @Autowired EventRepository events;
    @Autowired JdbcClient jdbc;
    @Autowired ObjectMapper mapper;
    @Autowired org.springframework.transaction.support.TransactionTemplate transaction;
    final AlertConverter converter = new AlertConverter();
    final String prefix = "sem147-repo-" + UUID.randomUUID() + "-";

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        PostgresEventRepositoryTests.databaseProperties(registry);
    }

    @AfterEach
    void removeOnlyThisTestsRows() {
        jdbc.sql("DELETE FROM alerts WHERE event_id LIKE :prefix").param("prefix", prefix + "%").update();
        jdbc.sql("DELETE FROM events WHERE event_id LIKE :prefix").param("prefix", prefix + "%").update();
    }

    Event storedEvent(String id) {
        var details = new LinkedHashMap<String, Object>();
        details.put("source_ip", "203.0.113.7");
        details.put("score", new BigDecimal("7.50"));
        details.put("nested", Map.of("ports", List.of(22, 2222)));
        var event = new Event(prefix + id, "2026-11-24T12:00:00Z", "honeypot", "ssh_login_attempt", "high",
            "Login attempt", "Repository check", details);
        events.save(event);
        return event;
    }

    @Test
    void storesTheGeneratedAlertAndReturnsItUnchanged() {
        var alert = converter.convert(storedEvent("a"));
        assertEquals(AlertRepository.SaveResult.CREATED, alerts.insertIfAbsent(alert));
        var stored = alerts.findById((String) alert.get("alert_id")).orElseThrow();
        assertEquals(mapper.valueToTree(alert), mapper.valueToTree(stored));
        assertEquals(new BigDecimal("7.50"), ((Map<?, ?>) stored.get("details")).get("score"));
        assertTrue(alerts.findAll().stream().anyMatch(listed -> listed.equals(stored)));
    }

    @Test
    void keepsTheFirstAlertForAnEvent() {
        var alert = converter.convert(storedEvent("b"));
        alerts.insertIfAbsent(alert);
        var changed = new LinkedHashMap<>(alert);
        changed.put("title", "Different converter output");
        assertEquals(AlertRepository.SaveResult.UNCHANGED, alerts.insertIfAbsent(changed));
        assertEquals("Login attempt", alerts.findById((String) alert.get("alert_id")).orElseThrow().get("title"));
        assertEquals(1L, jdbc.sql("SELECT count(*) FROM alerts WHERE event_id = :id")
            .param("id", alert.get("event_id")).query(Long.class).single());
    }

    @Test
    void rejectsAlertsWithoutTheirEventOrWithAMismatchedIdentity() {
        var orphan = converter.convert(new Event(prefix + "missing", "2026-11-24T12:00:00Z", "honeypot",
            "ssh_login_attempt", "high", "Login attempt", "No stored event", Map.of()));
        assertThrows(DataIntegrityViolationException.class, () -> alerts.insertIfAbsent(orphan));
        var mismatched = new LinkedHashMap<>(converter.convert(storedEvent("c")));
        mismatched.put("alert_id", "SIEM-ALERT-forged");
        mismatched.put("event_id", prefix + "other");
        assertThrows(DataIntegrityViolationException.class, () -> alerts.insertIfAbsent(mismatched));
    }

    @Test
    void alertIdAlreadyUsedByAnotherEventIsAnIntegrityErrorNotAReplay() {
        var first = converter.convert(storedEvent("d1"));
        alerts.insertIfAbsent(first);
        var colliding = new LinkedHashMap<>(converter.convert(storedEvent("d2")));
        colliding.put("alert_id", first.get("alert_id"));
        assertThrows(DataIntegrityViolationException.class, () -> alerts.insertIfAbsent(colliding));
        assertEquals(0L, jdbc.sql("SELECT count(*) FROM alerts WHERE event_id = :id")
            .param("id", colliding.get("event_id")).query(Long.class).single());
    }

    @Test
    void failedAlertInsertRollsBackTheEventInPostgres() {
        AlertRepository failing = new AlertRepository() {
            public SaveResult insertIfAbsent(Map<String, Object> alert) {
                alerts.insertIfAbsent(alert); // the row is written inside the transaction, then the store fails
                throw new org.springframework.dao.DataAccessResourceFailureException("connection lost after insert");
            }
            public List<Map<String, Object>> findAll() { throw new UnsupportedOperationException(); }
            public java.util.Optional<Map<String, Object>> findById(String id) { throw new UnsupportedOperationException(); }
        };
        var factory = new org.springframework.beans.factory.support.StaticListableBeanFactory();
        factory.addBean("events", events);
        var service = new com.ciberurjc.siem.services.EventService(factory.getBeanProvider(EventRepository.class), failing,
            converter, new com.ciberurjc.siem.services.AlertService(notification -> {}),
            new com.ciberurjc.siem.services.RepeatedAuthenticationFailureEvaluator(), transaction);
        var event = new Event(prefix + "rollback", "2026-11-24T12:00:00Z", "honeypot", "ssh_login_attempt", "high",
            "Login attempt", "Rollback check", Map.of("source_ip", "203.0.113.9"));
        assertThrows(com.ciberurjc.siem.services.EventStorageUnavailableException.class, () -> service.processIncomingEvent(event));
        assertTrue(events.findById(event.source(), event.event_id()).isEmpty(), "event must roll back with its alert");
        assertEquals(0L, jdbc.sql("SELECT count(*) FROM alerts WHERE event_id = :id")
            .param("id", event.event_id()).query(Long.class).single());
    }

    @Test
    void unknownAlertIsEmpty() {
        assertTrue(alerts.findById("SIEM-ALERT-" + prefix).isEmpty());
    }

    @Test
    void startupFailsWhenMigration005IsMissing() {
        String schema = "sem147_no_alerts_" + UUID.randomUUID().toString().replace("-", "");
        jdbc.sql("CREATE SCHEMA " + schema).update();
        try {
            String url = System.getenv("SIEM_TEST_DB_URL");
            var dataSource = new DriverManagerDataSource(url + (url.contains("?") ? "&" : "?") + "currentSchema=" + schema,
                System.getenv("SIEM_TEST_DB_USER"), System.getenv("SIEM_TEST_DB_PASSWORD"));
            var failure = assertThrows(IllegalStateException.class,
                () -> new PostgresAlertRepository(JdbcClient.create(dataSource), mapper, dataSource));
            assertTrue(failure.getMessage().contains("005-create-alerts.sql"));
        } finally {
            jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update();
        }
    }
}
