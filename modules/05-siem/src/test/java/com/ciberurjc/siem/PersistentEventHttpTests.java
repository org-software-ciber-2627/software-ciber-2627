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
import java.math.BigDecimal;
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
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("persistence")
@EnabledIfEnvironmentVariable(named = "SIEM_TEST_DB_URL", matches = ".+")
class PersistentEventHttpTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcClient jdbc;
    @Autowired EventRepository repository;
    final HttpClient client = HttpClient.newHttpClient();
    final String prefix = "sem65-http-" + UUID.randomUUID() + "-";
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
    void removeOnlyThisTestsEvents() {
        jdbc.sql("DELETE FROM events WHERE event_id LIKE :prefix").param("prefix", prefix + "%").update();
    }

    Map<String, Object> event(String filename) throws Exception {
        Map<String, Object> event = mapper.readValue(Files.readString(Path.of("contract/examples", filename)), Map.class);
        event.put("event_id", prefix + event.get("event_id"));
        return event;
    }

    HttpRequest postRequest(String body) {
        return HttpRequest.newBuilder(URI.create(baseUrl + "/events"))
            .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    HttpResponse<String> post(Map<String, Object> event) throws Exception {
        return client.send(postRequest(mapper.writeValueAsString(event)), HttpResponse.BodyHandlers.ofString());
    }

    long count() {
        return jdbc.sql("SELECT count(*) FROM events WHERE event_id LIKE :prefix")
            .param("prefix", prefix + "%").query(Long.class).single();
    }

    @Test
    void storesEveryProducerBeforeReturningReceiptAndLeavesAlertsUnchanged() throws Exception {
        var alertsRequest = HttpRequest.newBuilder(URI.create(baseUrl + "/alerts")).GET().build();
        String before = client.send(alertsRequest, HttpResponse.BodyHandlers.ofString()).body();
        for (String filename : List.of("grupo_2_ids_ejemplo_propuesto.json", "grupo_3_honeypot.json", "grupo_4_scanner.json")) {
            var input = event(filename);
            var response = post(input);
            assertEquals(200, response.statusCode(), response.body());
            assertEquals(Map.of("status", "success", "message", "Event stored successfully", "event_id", input.get("event_id")),
                mapper.readValue(response.body(), Map.class));
            var stored = repository.findById((String) input.get("source"), (String) input.get("event_id")).orElseThrow();
            assertEquals(mapper.readTree(mapper.writeValueAsString(input)), mapper.readTree(mapper.writeValueAsString(stored)));
            assertEquals(200, post(input).statusCode());
        }
        assertEquals(3, count());
        assertEquals(before, client.send(alertsRequest, HttpResponse.BodyHandlers.ofString()).body());
    }

    @Test
    void rejectsEveryChangedPayloadFieldWithoutOverwritingOriginal() throws Exception {
        var input = event("grupo_3_honeypot.json");
        assertEquals(200, post(input).statusCode());
        var changes = Map.<String, Object>of("timestamp", "2026-10-22T12:00:00.123456789Z",
            "event_type", "changed_type", "severity", "critical", "title", "Changed title",
            "description", "Changed description", "details", Map.of("changed", true));
        for (var change : changes.entrySet()) {
            var changed = new LinkedHashMap<>(input);
            changed.put(change.getKey(), change.getValue());
            var response = post(changed);
            assertEquals(409, response.statusCode(), change.getKey() + response.body());
            assertEquals("EVENT_ID_CONFLICT", mapper.readTree(response.body()).get("error").get("code").asText());
        }
        assertEquals(1, count());
        assertEquals(200, post(input).statusCode());
        var stored = repository.findById((String) input.get("source"), (String) input.get("event_id")).orElseThrow();
        assertEquals(mapper.readTree(mapper.writeValueAsString(input)), mapper.readTree(mapper.writeValueAsString(stored)));
    }

    @Test
    void acceptsSameIdentifierFromDifferentSources() throws Exception {
        var input = event("grupo_3_honeypot.json");
        for (String source : List.of("ids", "honeypot", "scanner")) {
            input.put("source", source);
            assertEquals(200, post(input).statusCode());
        }
        assertEquals(3, count());
    }

    @Test
    void comparesJsonSemanticallyAndPreservesNanosecondTimestamp() throws Exception {
        var input = event("grupo_3_honeypot.json");
        input.put("timestamp", "2026-10-22T12:00:00.123456789Z");
        input.put("details", mapper.readValue("{\"a\":1.0,\"b\":[null,true,\"ñ\"]}", Map.class));
        assertEquals(200, post(input).statusCode());
        input.put("details", mapper.readValue("{\"b\":[null,true,\"ñ\"],\"a\":1}", Map.class));
        assertEquals(200, post(input).statusCode());
        input.put("details", mapper.readValue("{\"b\":[true,null,\"ñ\"],\"a\":1}", Map.class));
        assertEquals(409, post(input).statusCode());
        assertEquals(1, count());
        assertEquals("2026-10-22T12:00:00.123456789Z", repository.findById((String) input.get("source"),
            (String) input.get("event_id")).orElseThrow().timestamp());
    }

    @Test
    void preservesPreciseDecimalValuesAndDetectsSmallChanges() throws Exception {
        var input = event("grupo_3_honeypot.json");
        var exact = new BigDecimal("1234567890.12345678901234567890");
        input.put("details", Map.of("precise", exact));
        assertEquals(200, post(input).statusCode());
        assertEquals(exact, repository.findById((String) input.get("source"),
            (String) input.get("event_id")).orElseThrow().details().get("precise"));
        input.put("details", Map.of("precise", new BigDecimal("1234567890.12345678901234567891")));
        assertEquals(409, post(input).statusCode());
        assertEquals(1, count());
    }

    @Test
    void acceptsReplayOfLegacySqlEventWithoutOriginalTimestamp() throws Exception {
        var input = event("grupo_3_honeypot.json");
        input.put("timestamp", "2026-10-22T12:00:00.100Z");
        assertEquals(200, post(input).statusCode());
        jdbc.sql("UPDATE events SET original_timestamp = NULL WHERE source = :source AND event_id = :id")
            .param("source", input.get("source")).param("id", input.get("event_id")).update();
        assertEquals(200, post(input).statusCode());
        assertEquals(1, count());
    }

    @Test
    void concurrentIdenticalReplaysProduceOneStoredEvent() throws Exception {
        String body = mapper.writeValueAsString(event("grupo_2_ids_ejemplo_propuesto.json"));
        var requests = new ArrayList<CompletableFuture<HttpResponse<String>>>();
        for (int i = 0; i < 12; i++) requests.add(client.sendAsync(postRequest(body), HttpResponse.BodyHandlers.ofString()));
        for (var pending : requests) assertEquals(200, pending.join().statusCode());
        assertEquals(1, count());
    }

    @Test
    void concurrentDifferentPayloadsKeepOneWinner() throws Exception {
        var input = event("grupo_3_honeypot.json");
        var requests = new ArrayList<CompletableFuture<HttpResponse<String>>>();
        for (int i = 0; i < 8; i++) {
            input.put("title", "Concurrent event " + i);
            requests.add(client.sendAsync(postRequest(mapper.writeValueAsString(input)), HttpResponse.BodyHandlers.ofString()));
        }
        var statuses = requests.stream().map(pending -> pending.join().statusCode()).toList();
        assertEquals(1, statuses.stream().filter(status -> status == 200).count());
        assertEquals(7, statuses.stream().filter(status -> status == 409).count());
        assertEquals(1, count());
    }

    @Test
    void preservesOriginalIdentifierWithLogSeparatorsAcrossHttpStorageAndReplay() throws Exception {
        var input = event("grupo_3_honeypot.json");
        input.put("event_id", prefix + "id\r\nFORGED\u0085\u2028\u2029");
        var response = post(input);
        assertEquals(200, response.statusCode());
        assertEquals(input.get("event_id"), mapper.readTree(response.body()).get("event_id").asText());
        assertEquals(input.get("event_id"), repository.findById((String) input.get("source"),
            (String) input.get("event_id")).orElseThrow().event_id());
        assertEquals(200, post(input).statusCode());
        assertEquals(1, count());
    }

    @Test
    void rejectsInvalidEventsBeforePersisting() throws Exception {
        var input = event("grupo_3_honeypot.json");
        for (var invalid : Map.<String, Object>of("timestamp", "not-a-date", "severity", "urgent", "source", "identity", "title", " ").entrySet()) {
            var changed = new LinkedHashMap<>(input);
            changed.put(invalid.getKey(), invalid.getValue());
            assertEquals(400, post(changed).statusCode());
        }
        assertEquals(0, count());
    }
}
