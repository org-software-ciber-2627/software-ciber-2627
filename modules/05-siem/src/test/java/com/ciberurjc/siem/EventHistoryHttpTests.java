package com.ciberurjc.siem;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.dao.QueryTimeoutException;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

// Real HTTP and serialization, with a test repository rather than PostgreSQL.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=127.0.0.1")
@Import(EventHistoryHttpTests.Storage.class)
class EventHistoryHttpTests {
    @TestConfiguration(proxyBeanMethods = false)
    static class Storage {
        @Bean
        EventHistoryServiceTests.FakeRepository historyRepository() {
            return new EventHistoryServiceTests.FakeRepository();
        }
    }

    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    @Autowired EventHistoryServiceTests.FakeRepository repository;
    final HttpClient client = HttpClient.newHttpClient();

    @BeforeEach
    void resetRepository() {
        repository.events = List.of();
        repository.failure = null;
        repository.calls = 0;
    }

    HttpResponse<String> get(String suffix) throws Exception {
        return getPath("/events" + suffix);
    }

    HttpResponse<String> getPath(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" +
                environment.getProperty("local.server.port") + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void defaultsEmptyAndPagedResultsKeepTheirJsonContract() throws Exception {
        var empty = get("");
        assertEquals(200, empty.statusCode());
        assertEquals(mapper.readTree("{\"events\":[],\"next_offset\":null,\"next\":null}"), mapper.readTree(empty.body()));
        assertEquals("no-store", empty.headers().firstValue("Cache-Control").orElseThrow());
        assertEquals(101, repository.requestedLimit);
        assertEquals(0, repository.requestedOffset);
        repository.events = List.of(EventHistoryServiceTests.event("one"), EventHistoryServiceTests.event("two"));
        var first = get("?limit=1&offset=0");
        assertEquals(200, first.statusCode());
        var page = mapper.readTree(first.body());
        assertEquals(1, page.get("events").size());
        assertEquals(1, page.get("next_offset").asInt());
        assertEquals("/events?limit=1&offset=1", page.get("next").asText());
        assertEquals(mapper.readTree(mapper.writeValueAsString(repository.events.getFirst())), page.get("events").get(0));
        var last = mapper.readTree(getPath(page.get("next").asText()).body());
        assertEquals("two", last.get("events").get(0).get("event_id").asText());
        assertTrue(last.get("next_offset").isNull());
        assertTrue(last.get("next").isNull());
        assertTrue(mapper.readTree(get("?limit=1&offset=9").body()).get("events").isEmpty());
    }

    @Test
    void invalidAndInjectionShapedParametersNeverReachTheRepository() throws Exception {
        for (String suffix : List.of("?limit=", "?offset=", "?limit=0", "?limit=501", "?offset=-1",
                "?limit=1.5", "?limit=1&limit=2", "?offset=0&offset=0", "?order=event_id", "?limit",
                "?offset=0%20OR%201%3D1", "?offset=0%3BDROP%20TABLE%20events", "?limit=%27",
                "?offset=9223372036854775807", "?offset=9223372036854775808")) {
            var response = get(suffix);
            assertEquals(400, response.statusCode(), suffix + ": " + response.body());
            assertEquals("VALIDATION_ERROR", mapper.readTree(response.body()).get("error").get("code").asText());
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        }
        assertEquals(0, repository.calls);
    }

    @Test
    void storageFailuresAndQueryDefectsAreGenericAndHaveDifferentStatuses() throws Exception {
        for (RuntimeException failure : List.of(new DataAccessResourceFailureException("private-sql-marker"),
                new QueryTimeoutException("private-sql-marker"), new InvalidDataAccessResourceUsageException("private-sql-marker"))) {
            repository.failure = failure;
            var response = get("");
            int expected = failure instanceof InvalidDataAccessResourceUsageException ? 500 : 503;
            assertEquals(expected, response.statusCode(), response.body());
            assertEquals(expected == 500 ? "INTERNAL_ERROR" : "STORAGE_UNAVAILABLE",
                    mapper.readTree(response.body()).get("error").get("code").asText());
            assertFalse(response.body().contains("private-sql-marker"));
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        }
    }

    @Test
    void nextPreservesLimitAndAdvancesAnExplicitOffset() throws Exception {
        repository.events = java.util.stream.IntStream.range(0, 5)
                .mapToObj(i -> EventHistoryServiceTests.event("event-" + i)).toList();
        var first = mapper.readTree(get("?limit=2&offset=1").body());
        assertEquals("/events?limit=2&offset=3", first.get("next").asText());
        var response = getPath(first.get("next").asText());
        assertEquals(200, response.statusCode());
        var last = mapper.readTree(response.body());
        assertEquals(2, last.get("events").size());
        assertEquals("event-3", last.get("events").get(0).get("event_id").asText());
        assertEquals("event-4", last.get("events").get(1).get("event_id").asText());
        assertTrue(last.get("next").isNull());
        assertTrue(last.get("next_offset").isNull());
    }

    @Test
    void defaultNextDoesNotUseForwardedHostHeaders() throws Exception {
        repository.events = java.util.stream.IntStream.range(0, 101)
                .mapToObj(i -> EventHistoryServiceTests.event("event-" + i)).toList();
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" +
                environment.getProperty("local.server.port") + "/events"))
                .header("X-Forwarded-Host", "untrusted.domain.local")
                .header("X-Forwarded-Proto", "https").GET().build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertEquals("/events?limit=100&offset=100", mapper.readTree(response.body()).get("next").asText());
        assertFalse(response.body().contains("untrusted.domain.local"));
    }

}
