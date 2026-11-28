package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
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
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import javax.sql.DataSource;
import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

// Run only against the dedicated disposable database created by test-storage.py.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "server.address=127.0.0.1")
@ActiveProfiles("persistence")
@EnabledIfEnvironmentVariable(named = "SIEM_TEST_DB_URL", matches = ".+")
class EventHistoryPostgresHttpTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    @Autowired EventRepository repository;
    @Autowired JdbcClient jdbc;
    @Autowired DataSource dataSource;
    final HttpClient client = HttpClient.newHttpClient();
    final String prefix = "sem99-" + UUID.randomUUID() + "-";
    URI origin;

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        PostgresEventRepositoryTests.databaseProperties(registry);
    }

    @BeforeEach
    void requireEmptyDisposableDatabase() {
        origin = URI.create("http://127.0.0.1:" + environment.getProperty("local.server.port"));
        assertEquals(0L, jdbc.sql("SELECT count(*) FROM events").query(Long.class).single(),
                "History integration tests require a dedicated empty database");
    }

    @AfterEach
    void removeOnlyOwnedRows() {
        jdbc.sql("DELETE FROM events WHERE event_id LIKE :prefix").param("prefix", prefix + "%").update();
    }

    Event event(String id, String source, String timestamp) {
        var details = new LinkedHashMap<String, Object>();
        details.put("nested", java.util.Arrays.asList(null, true, 42, "Unicode ñ"));
        details.put("decimal", new BigDecimal("1234567890.12345678901234567890"));
        return new Event(prefix + id, timestamp, source, "history_fixture", "low", "History fixture",
                "Disposable database acceptance fixture", details);
    }

    HttpResponse<String> get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofSeconds(15))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    JsonNode page(String path) throws Exception {
        var response = get(path);
        assertEquals(200, response.statusCode(), response.body());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        return mapper.readTree(response.body());
    }

    HttpResponse<String> post(Event event) throws Exception {
        return client.send(HttpRequest.newBuilder(origin.resolve("/events"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(event))).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void emptyDatabaseAndLargestSafeOffsetReturnEmptyPages() throws Exception {
        var expected = mapper.readTree("{\"events\":[],\"next_offset\":null,\"next\":null}");
        assertEquals(expected, page("/events"));
        assertEquals(expected, page("/events?limit=1&offset=9223372036854775806"));
    }

    @Test
    void followsReturnedLinksWithDateSourceAndIdentifierTieBreakers() throws Exception {
        var newest = event("z-new", "scanner", "2099-10-30T12:00:00.123456789Z");
        var honeypot = event("shared", "honeypot", "2099-10-29T12:00:00Z");
        var idsA = event("a", "ids", "2099-10-29T12:00:00Z");
        var idsB = event("b", "ids", "2099-10-29T12:00:00Z");
        var scanner = event("shared", "scanner", "2099-10-29T12:00:00Z");
        var oldest = event("old", "ids", "2099-10-28T12:00:00Z");
        for (var input : List.of(oldest, idsB, scanner, honeypot, newest, idsA)) {
            assertEquals(200, post(input).statusCode());
            assertEquals(200, post(input).statusCode());
        }
        var actual = new ArrayList<JsonNode>();
        String path = "/events?limit=2";
        for (int i = 0; i < 3; i++) {
            var current = page(path);
            assertEquals(2, current.get("events").size());
            current.get("events").forEach(actual::add);
            if (i < 2) {
                int offset = (i + 1) * 2;
                assertEquals(offset, current.get("next_offset").asInt());
                path = current.get("next").asText();
                assertEquals("/events?limit=2&offset=" + offset, path);
            } else {
                assertTrue(current.get("next").isNull());
                assertTrue(current.get("next_offset").isNull());
            }
        }
        var expected = new ArrayList<JsonNode>();
        for (var input : List.of(newest, honeypot, idsA, idsB, scanner, oldest)) {
            expected.add(mapper.readTree(mapper.writeValueAsString(input)));
        }
        assertEquals(expected, actual);
        assertEquals(6L, jdbc.sql("SELECT count(*) FROM events").query(Long.class).single());
        var beyond = page("/events?offset=6");
        assertTrue(beyond.get("events").isEmpty());
        assertTrue(beyond.get("next").isNull());
        assertTrue(beyond.get("next_offset").isNull());
        var invalid = new Event(prefix + "invalid", oldest.timestamp(), "ids", "test", "low", " ",
                "Invalid fixture", oldest.details());
        assertEquals(400, post(invalid).statusCode());
        assertEquals(6, page("/events").get("events").size());
    }

    @Test
    void maximumPageAndDefaultPageKeepTheExtraRowAvailable() throws Exception {
        jdbc.sql("""
            INSERT INTO events (source, event_id, occurred_at, event_type, severity, title, description, details, original_timestamp)
            SELECT 'ids', :prefix || lpad(n::text, 4, '0'), '2099-10-29T12:00:00Z'::timestamptz,
                   'history_fixture', 'low', 'History fixture', 'Pagination fixture', '{}'::jsonb,
                   '2099-10-29T12:00:00Z'
            FROM generate_series(0, 500) AS n
            """).param("prefix", prefix).update();
        var defaults = page("/events");
        assertEquals(100, defaults.get("events").size());
        assertEquals("/events?limit=100&offset=100", defaults.get("next").asText());
        var first = page("/events?limit=500");
        assertEquals(500, first.get("events").size());
        assertEquals(500, first.get("next_offset").asInt());
        assertEquals("/events?limit=500&offset=500", first.get("next").asText());
        var last = page(first.get("next").asText());
        assertEquals(1, last.get("events").size());
        assertEquals(prefix + "0500", last.get("events").get(0).get("event_id").asText());
        assertTrue(last.get("next").isNull());
        assertTrue(last.get("next_offset").isNull());
    }

    @Test
    void historyReadsLegacyTimestampAndPreservesNestedValues() throws Exception {
        var input = event("legacy", "ids", "2099-10-29T12:00:00.123456Z");
        assertEquals(200, post(input).statusCode());
        jdbc.sql("UPDATE events SET original_timestamp = NULL WHERE source = :source AND event_id = :id")
                .param("source", input.source()).param("id", input.event_id()).update();
        var result = page("/events?limit=1");
        var expected = mapper.readTree(mapper.writeValueAsString(input));
        assertEquals(expected, result.get("events").get(0));
        assertTrue(result.get("next").isNull());
    }

    @Test
    void rejectsInvalidQueriesWithoutChangingPersistentHistory() throws Exception {
        var input = event("valid", "scanner", "2099-10-29T12:00:00Z");
        assertEquals(200, post(input).statusCode());
        for (var suffix : List.of("?limit=", "?limit=0", "?limit=501", "?offset=-1", "?limit=1.5",
                "?limit=1&limit=2", "?offset=0&offset=0", "?order=source", "?offset=9223372036854775807",
                "?offset=0%3BDROP%20TABLE%20events", "?offset=0%20OR%201%3D1")) {
            var response = get("/events" + suffix);
            assertEquals(400, response.statusCode(), suffix + response.body());
            assertEquals("VALIDATION_ERROR", mapper.readTree(response.body()).get("error").get("code").asText());
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        }
        assertEquals(1, page("/events").get("events").size());
        assertEquals(input, repository.findById(input.source(), input.event_id()).orElseThrow());
    }

    @Test
    void realBlockedReadTimesOutAndRecoversAfterLockRelease() throws Exception {
        var input = event("timeout", "ids", "2099-10-29T12:00:00Z");
        assertEquals(200, post(input).statusCode());
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            connection.setAutoCommit(false);
            try {
                statement.execute("SET LOCAL lock_timeout = '2s'");
                statement.execute("LOCK TABLE events IN ACCESS EXCLUSIVE MODE");
                long started = System.nanoTime();
                var response = get("/events");
                long elapsed = Duration.ofNanos(System.nanoTime() - started).toMillis();
                assertEquals(503, response.statusCode(), response.body());
                assertEquals("STORAGE_UNAVAILABLE", mapper.readTree(response.body()).get("error").get("code").asText());
                assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
                assertFalse(response.body().contains("SELECT"));
                assertTrue(elapsed >= 4000 && elapsed < 15000, "Unexpected timeout duration: " + elapsed);
            } finally {
                connection.rollback();
            }
        }
        assertEquals(1, page("/events").get("events").size());
    }
}
