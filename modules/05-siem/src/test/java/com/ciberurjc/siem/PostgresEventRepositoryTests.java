package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.repositories.EventRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("persistence")
@EnabledIfEnvironmentVariable(named = "SIEM_TEST_DB_URL", matches = ".+")
class PostgresEventRepositoryTests {
    @Autowired EventRepository repository;
    @Autowired JdbcClient jdbc;
    @Autowired ObjectMapper mapper;
    final String prefix = "sem64-test-" + UUID.randomUUID() + "-";

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        registry.add("siem.database.url", () -> System.getenv("SIEM_TEST_DB_URL"));
        registry.add("siem.database.username", () -> System.getenv("SIEM_TEST_DB_USER"));
        registry.add("siem.database.password", () -> System.getenv("SIEM_TEST_DB_PASSWORD"));
    }

    @AfterEach
    void removeOnlyThisTestsEvents() {
        jdbc.sql("DELETE FROM events WHERE event_id LIKE :prefix")
            .param("prefix", prefix + "%").update();
    }

    Event event(String id, String source, String timestamp) {
        return new Event(prefix + id, timestamp, source, "port_scan", "medium",
            "Persistence check", "Repository integration check", new LinkedHashMap<>());
    }

    @Test
    void storesAndRecoversAllProducerExamples() throws Exception {
        for (String filename : List.of("grupo_2_ids_ejemplo_propuesto.json", "grupo_3_honeypot.json", "grupo_4_scanner.json")) {
            Event fixture = mapper.readValue(Files.readString(Path.of("contract/examples", filename)), Event.class);
            Event input = new Event(prefix + fixture.event_id(), fixture.timestamp(), fixture.source(),
                fixture.event_type(), fixture.severity(), fixture.title(), fixture.description(), fixture.details());
            repository.save(input);
            Event actual = repository.findById(input.source(), input.event_id()).orElseThrow();
            assertEquals(input, actual, filename);
        }
    }

    @Test
    void preservesNestedJsonNullsUnicodeAndExactDecimalValues() {
        var details = new LinkedHashMap<String, Object>();
        details.put("text", "Unicode ñ and apostrophe ' stay intact");
        details.put("nullable", null);
        var nested = new ArrayList<Object>();
        nested.add(true);
        nested.add(42);
        nested.add(null);
        nested.add(new BigDecimal("1234567890.12345678901234567890"));
        details.put("nested", nested);
        Event input = new Event(prefix + "json", "2026-10-20T12:00:00Z", "honeypot", "auth_failure",
            "high", "JSON check", "Preserve every JSON value", details);
        repository.save(input);
        Event actual = repository.findById(input.source(), input.event_id()).orElseThrow();
        assertEquals(details, actual.details());
    }

    @Test
    void preservesOriginalTimestampIncludingNanosecondsAndFormatting() {
        for (String timestamp : List.of("2026-10-20T12:00:00.123456789Z", "2026-10-20T12:00:00.000Z")) {
            Event input = event(UUID.randomUUID().toString(), "ids", timestamp);
            repository.save(input);
            assertEquals(timestamp, repository.findById(input.source(), input.event_id()).orElseThrow().timestamp());
        }
    }

    @Test
    void rejectsSameProducerDuplicateWithoutOverwritingIt() {
        Event original = event("duplicate", "ids", "2026-10-20T12:00:00Z");
        repository.save(original);
        Event changed = new Event(original.event_id(), original.timestamp(), original.source(), original.event_type(),
            "critical", "Changed event", original.description(), original.details());
        assertThrows(DuplicateKeyException.class, () -> repository.save(changed));
        assertEquals(original, repository.findById(original.source(), original.event_id()).orElseThrow());
    }

    @Test
    void storesSameIdentifierForDifferentProducers() {
        Event ids = event("shared", "ids", "2026-10-20T12:00:00Z");
        Event honeypot = event("shared", "honeypot", "2026-10-20T12:00:00Z");
        repository.save(ids);
        repository.save(honeypot);
        assertEquals(ids, repository.findById("ids", ids.event_id()).orElseThrow());
        assertEquals(honeypot, repository.findById("honeypot", honeypot.event_id()).orElseThrow());
    }

    @Test
    void returnsEmptyForUnknownPair() {
        Event input = event("lookup", "ids", "2026-10-20T12:00:00Z");
        repository.save(input);
        assertTrue(repository.findById("honeypot", input.event_id()).isEmpty());
        assertTrue(repository.findById("ids", prefix + "unknown").isEmpty());
    }

    @Test
    void treatsIdentifiersAndTextAsDataRatherThanSql() {
        Event input = new Event(prefix + "'; DROP TABLE events; --", "2026-10-20T12:00:00Z", "scanner",
            "vulnerability_detected", "low", "O'Brien", "Quotes ' and ; are event data", new LinkedHashMap<>());
        repository.save(input);
        assertEquals(input, repository.findById(input.source(), input.event_id()).orElseThrow());
        assertTrue(repository.findById("ids' OR '1'='1", input.event_id()).isEmpty());
    }

    @Test
    void rejectsInvalidTimestampBeforeSavingAnything() {
        Event invalid = event("invalid-time", "ids", "not-a-timestamp");
        assertThrows(DateTimeParseException.class, () -> repository.save(invalid));
        assertTrue(repository.findById("ids", invalid.event_id()).isEmpty());
    }

    @Test
    void propagatesConstraintFailuresWithoutReportingSuccess() {
        Event invalid = event("invalid-source", "unknown", "2026-10-20T12:00:00Z");
        assertThrows(DataAccessException.class, () -> repository.save(invalid));
        assertTrue(repository.findById("unknown", invalid.event_id()).isEmpty());
    }

    @Test
    void readsEventsInsertedBeforeOriginalTimestampColumnWasAdded() {
        String id = prefix + "legacy";
        jdbc.sql("""
            INSERT INTO events (source, event_id, occurred_at, event_type, severity, title, description, details)
            VALUES ('ids', :id, '2026-10-20T12:00:00Z', 'port_scan', 'low', 'Legacy event', 'SQL insert', '{}')
            """).param("id", id).update();
        Event actual = repository.findById("ids", id).orElseThrow();
        assertEquals(Instant.parse("2026-10-20T12:00:00Z"), Instant.parse(actual.timestamp()));
        assertEquals(id, actual.event_id());
    }
}
