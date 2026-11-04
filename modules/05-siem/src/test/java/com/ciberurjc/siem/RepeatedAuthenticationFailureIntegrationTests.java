package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.services.RepeatedAuthenticationFailureEvaluator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import tools.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RepeatedAuthenticationFailureIntegrationTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    @Autowired RepeatedAuthenticationFailureEvaluator evaluator;
    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void springComponentEvaluatesTheSameP004ThatHttpAcceptsWithoutChangingItsReceipt() throws Exception {
        var event = fixture();
        var expected = evaluator.evaluate(event).orElseThrow();
        assertEquals(BigInteger.valueOf(12), expected.attempts().orElseThrow());
        String alertsBefore = getAlerts();
        for (int attempt = 0; attempt < 2; attempt++) {
            var response = post(event);
            assertEquals(200, response.statusCode(), response.body());
            assertEquals(Map.of("status", "success", "message", "Event received successfully (mock)",
                "event_id", event.event_id()), mapper.readValue(response.body(), Map.class));
            // Evaluation is explicit; the HTTP mock does not yet consume the result.
            assertEquals(expected, evaluator.evaluate(event).orElseThrow());
        }
        assertEquals(mapper.readTree(alertsBefore), mapper.readTree(getAlerts()));
    }

    @Test
    void incompleteOrIncoherentDetailsDoNotBecomeNewHttp400Requirements() throws Exception {
        var base = fixture();
        int variant = 0;
        for (Map<String, Object> details : List.of(Map.<String, Object>of("rule_id", "P004"),
                Map.<String, Object>of("rule_id", "P004", "attempts", "PRIVATE_VALUE", "source_ip", 42))) {
            var event = new Event(base.event_id() + "-metadata-" + variant++, base.timestamp(), "ids", "brute_force",
                base.severity(), base.title(), base.description(), details);
            var response = post(event);
            assertEquals(200, response.statusCode(), response.body());
            var result = evaluator.evaluate(event).orElseThrow();
            assertTrue(result.attempts().isEmpty());
            assertFalse(result.toString().contains("PRIVATE_VALUE"));
            assertFalse(response.body().contains("PRIVATE_VALUE"));
        }
    }

    @Test
    void existingSourcesRemainAcceptedButDoNotMatchP004AndIdentityRemainsRejected() throws Exception {
        var base = fixture();
        for (String source : List.of("honeypot", "scanner")) {
            var event = new Event(base.event_id(), base.timestamp(), source, "brute_force",
                base.severity(), base.title(), base.description(), base.details());
            assertTrue(evaluator.evaluate(event).isEmpty());
            assertEquals(200, post(event).statusCode());
        }
        var identity = new Event(base.event_id(), base.timestamp(), "identity", "brute_force",
            base.severity(), base.title(), base.description(), base.details());
        assertTrue(evaluator.evaluate(identity).isEmpty());
        assertEquals(400, post(identity).statusCode());
    }

    private Event fixture() throws Exception {
        try (var input = getClass().getResourceAsStream("/ids/p004.json")) {
            return mapper.readValue(input, Event.class);
        }
    }

    private HttpResponse<String> post(Event event) throws Exception {
        var request = HttpRequest.newBuilder(url("/events")).header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(event))).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private String getAlerts() throws Exception {
        return client.send(HttpRequest.newBuilder(url("/alerts")).GET().build(),
            HttpResponse.BodyHandlers.ofString()).body();
    }

    private URI url(String path) {
        return URI.create("http://127.0.0.1:" + environment.getProperty("local.server.port") + path);
    }
}
