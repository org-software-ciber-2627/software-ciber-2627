package com.ciberurjc.siem;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"server.address=127.0.0.1", "server.servlet.context-path=/siem"})
@Import(EventHistoryHttpTests.Storage.class)
class EventHistoryContextHttpTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    @Autowired EventHistoryServiceTests.FakeRepository repository;

    @Test
    void nextPreservesServletContextAndCanBeFollowed() throws Exception {
        repository.events = List.of(EventHistoryServiceTests.event("one"), EventHistoryServiceTests.event("two"));
        repository.failure = null;
        var origin = URI.create("http://127.0.0.1:" + environment.getProperty("local.server.port"));
        var client = HttpClient.newHttpClient();
        var first = client.send(HttpRequest.newBuilder(origin.resolve("/siem/events?limit=1")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, first.statusCode());
        String next = mapper.readTree(first.body()).get("next").asText();
        assertEquals("/siem/events?limit=1&offset=1", next);
        var response = client.send(HttpRequest.newBuilder(origin.resolve(next)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        var last = mapper.readTree(response.body());
        assertEquals("two", last.get("events").get(0).get("event_id").asText());
        assertTrue(last.get("next_offset").isNull());
        assertTrue(last.get("next").isNull());
    }
}
