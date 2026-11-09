package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.services.RepeatedAuthenticationFailureEvaluator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
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

@Import(InMemoryEventTestConfiguration.class)
@org.springframework.test.annotation.DirtiesContext(classMode = org.springframework.test.annotation.DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=127.0.0.1")
class RepeatedAuthenticationFailureIntegrationTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    @Autowired RepeatedAuthenticationFailureEvaluator evaluator;
    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void recognizesP004ThroughHttpAndDoesNotDuplicateItsAlert() throws Exception {
        var event = fixture();
        var expected = evaluator.evaluate(event).orElseThrow();
        assertEquals(BigInteger.valueOf(12), expected.attempts().orElseThrow());
        for (int attempt = 0; attempt < 2; attempt++) {
            var response = post(event);
            assertEquals(200, response.statusCode(), response.body());
            assertEquals(Map.of("status", "success", "message", "Event stored successfully",
                "event_id", event.event_id()), mapper.readValue(response.body(), Map.class));
        }
        var alerts = mapper.readTree(getAlerts()).get("alerts");
        assertEquals(1, alerts.size());
        var alert = alerts.get(0);
        assertEquals(event.event_id(), alert.get("event_id").asText());
        assertEquals(expected.sourceIp().orElseThrow(), alert.get("source_ip").asText());
    }

    @Test
    void incompleteOrIncoherentDetailsDoNotBecomeNewHttp400Requirements() throws Exception {
        var base = fixture();
        int variant = 0;
        for (Map<String, Object> details : List.of(Map.<String, Object>of("rule_id", "P004"),
                Map.<String, Object>of("rule_id", "P004", "attempts", "PRIVATE_VALUE", "source_ip", " "))) {
            var event = new Event(base.event_id() + "-metadata-" + variant++, base.timestamp(), "ids", "brute_force",
                base.severity(), base.title(), base.description(), details);
            var response = post(event);
            assertEquals(200, response.statusCode(), response.body());
            var result = evaluator.evaluate(event).orElseThrow();
            assertTrue(result.attempts().isEmpty());
            assertFalse(result.toString().contains("PRIVATE_VALUE"));
            assertFalse(response.body().contains("PRIVATE_VALUE"));
            var alert = mapper.readTree(getAlerts()).get("alerts").get(variant - 1);
            assertTrue(alert.get("source_ip").isNull());
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
