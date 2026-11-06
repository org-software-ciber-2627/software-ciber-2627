package com.ciberurjc.siem;

import com.ciberurjc.siem.repositories.EventRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

// Validates SIEM compatibility with synthetic scanner events, not a real scan.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=127.0.0.1")
@ActiveProfiles("persistence")
@EnabledIfEnvironmentVariable(named = "SIEM_TEST_DB_URL", matches = ".+")
class ScannerEventHttpTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcClient jdbc;
    @Autowired EventRepository repository;
    final HttpClient client = HttpClient.newHttpClient();
    final String prefix = "sem95-" + UUID.randomUUID() + "-";
    String baseUrl;

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        PostgresEventRepositoryTests.databaseProperties(registry);
    }

    @BeforeEach
    void configureUrl() {
        baseUrl = "http://127.0.0.1:" + environment.getProperty("local.server.port");
    }

    @AfterEach
    void removeOnlyOwnedRows() {
        jdbc.sql("DELETE FROM events WHERE event_id LIKE :prefix").param("prefix", prefix + "%").update();
    }

    Map<String, Object> event(String suffix) throws Exception {
        var input = mapper.readValue(Files.readString(Path.of("contract/examples/grupo_4_scanner_info.json")), Map.class);
        var event = new LinkedHashMap<String, Object>(input);
        event.put("event_id", prefix + suffix);
        return event;
    }

    HttpResponse<String> post(Object event) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(baseUrl + "/events"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(event))).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    String alerts() throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(baseUrl + "/alerts")).GET().build(),
                HttpResponse.BodyHandlers.ofString()).body();
    }

    long count() {
        return jdbc.sql("SELECT count(*) FROM events WHERE event_id LIKE :prefix")
                .param("prefix", prefix + "%").query(Long.class).single();
    }

    @Test
    void storesInformationalScannerEventsWithFaithfulFieldsAndNoNewAlerts() throws Exception {
        String before = alerts();
        for (String type : List.of("service_detected", "port_open")) {
            var input = event(type);
            input.put("event_type", type);
            var response = post(input);
            assertEquals(200, response.statusCode(), response.body());
            assertEquals(Map.of("status", "success", "message", "Event stored successfully", "event_id", input.get("event_id")),
                    mapper.readValue(response.body(), Map.class));
            var stored = repository.findById("scanner", (String) input.get("event_id")).orElseThrow();
            assertEquals("info", stored.severity());
            assertEquals(mapper.readTree(mapper.writeValueAsString(input)), mapper.readTree(mapper.writeValueAsString(stored)));
            assertEquals(200, post(input).statusCode());
        }
        assertEquals(2, count());
        assertEquals(mapper.readTree(before), mapper.readTree(alerts()));
    }

    @Test
    void acceptsTheCommonSeverityCatalogForEveryExistingSource() throws Exception {
        for (String source : List.of("ids", "honeypot", "scanner")) {
            for (String severity : List.of("info", "low", "medium", "high", "critical")) {
                var input = event(source + "-" + severity);
                input.put("source", source);
                input.put("severity", severity);
                assertEquals(200, post(input).statusCode(), source + ": " + severity);
                assertEquals(severity, repository.findById(source, (String) input.get("event_id")).orElseThrow().severity());
            }
        }
        assertEquals(15, count());
    }

    @Test
    void rejectsLegacyScannerShapeInvalidSeveritiesDatesAndReportsWithoutStorage() throws Exception {
        var valid = event("invalid");
        var cases = new ArrayList<Object>();
        var legacySource = new LinkedHashMap<>(valid);
        legacySource.put("source", "vulnerability_scanner");
        cases.add(legacySource);
        var rootTarget = new LinkedHashMap<>(valid);
        rootTarget.put("target", ((Map<?, ?>) valid.get("details")).get("target"));
        cases.add(rootTarget);
        for (Object severity : java.util.Arrays.asList("urgent", "INFO", "", null, 42)) {
            var invalid = new LinkedHashMap<>(valid);
            invalid.put("severity", severity);
            cases.add(invalid);
        }
        for (String timestamp : List.of("not-a-date", "2026-09-29T10:30:00+00:00")) {
            var invalid = new LinkedHashMap<>(valid);
            invalid.put("timestamp", timestamp);
            cases.add(invalid);
        }
        cases.add(Map.of("events", List.of(valid)));
        cases.add(List.of(valid));
        for (Object invalid : cases) {
            var response = post(invalid);
            assertEquals(400, response.statusCode(), response.body());
            String code = mapper.readTree(response.body()).get("error").get("code").asText();
            assertTrue(List.of("INVALID_JSON", "VALIDATION_ERROR").contains(code));
        }
        assertEquals(0, count());
    }

    @Test
    void changingInfoToLowIsAConflictAndCannotOverwriteTheOriginalEvent() throws Exception {
        var input = event("severity-conflict");
        assertEquals(200, post(input).statusCode());
        var changed = new LinkedHashMap<>(input);
        changed.put("severity", "low");
        var response = post(changed);
        assertEquals(409, response.statusCode());
        assertEquals("EVENT_ID_CONFLICT", mapper.readTree(response.body()).get("error").get("code").asText());
        assertEquals("info", repository.findById("scanner", (String) input.get("event_id")).orElseThrow().severity());
        assertEquals(200, post(input).statusCode());
        assertEquals(1, count());
    }
}
