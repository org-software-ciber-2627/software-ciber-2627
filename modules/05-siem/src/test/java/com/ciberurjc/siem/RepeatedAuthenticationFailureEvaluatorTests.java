package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.services.RepeatedAuthenticationFailureEvaluator;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RepeatedAuthenticationFailureEvaluatorTests {
    private static final String SECRET = "SECRET_DO_NOT_COPY";
    private final RepeatedAuthenticationFailureEvaluator evaluator = new RepeatedAuthenticationFailureEvaluator();

    @Test
    void recognizesTheDocumentedIdsDetectionAndPreservesItsAggregate() throws Exception {
        var event = fixture();
        var detection = evaluator.evaluate(event).orElseThrow();
        assertEquals("ids", detection.source());
        assertEquals(event.event_id(), detection.eventId());
        assertEquals(BigInteger.valueOf(12), detection.attempts().orElseThrow());
        assertEquals("122.5.240.60", detection.sourceIp().orElseThrow());
        assertEquals(BigInteger.valueOf(60), detection.windowSeconds().orElseThrow());
        assertEquals(Instant.parse("2026-04-20T13:50:10Z"), detection.firstAttempt().orElseThrow());
        assertEquals(Instant.parse("2026-04-20T13:51:02Z"), detection.lastAttempt().orElseThrow());
        assertTrue(detection.issues().isEmpty());
    }

    @Test
    void excludesPortAndEndpointScans() throws Exception {
        var portScan = JsonMapper.builder().build().readValue(Files.readString(
            Path.of("contract/examples/grupo_2_ids_ejemplo_propuesto.json")), Event.class);
        assertTrue(evaluator.evaluate(portScan).isEmpty());
        var event = fixture();
        assertTrue(evaluator.evaluate(event(event, "ids", "endpoint_scan", event.details())).isEmpty());
    }

    @Test
    void requiresTheExactSourceTypeAndRuleWithoutAliases() throws Exception {
        var event = fixture();
        for (String source : List.of("honeypot", "scanner", "identity", "IDS")) {
            assertTrue(evaluator.evaluate(event(event, source, "brute_force", event.details())).isEmpty(), source);
        }
        for (String type : List.of("failed_login", "successful_login", "fuerza_bruta", "BRUTE_FORCE")) {
            assertTrue(evaluator.evaluate(event(event, "ids", type, event.details())).isEmpty(), type);
        }
        for (Object rule : List.of("P005", "p004", " P004 ", 4, List.of("P004"))) {
            assertTrue(evaluator.evaluate(with(event, "rule_id", rule)).isEmpty());
        }
    }

    @Test
    void safelyIgnoresEventsWithoutRuleOrCommonIdentity() throws Exception {
        var event = fixture();
        assertTrue(evaluator.evaluate(null).isEmpty());
        assertTrue(evaluator.evaluate(event(event, "ids", "brute_force", null)).isEmpty());
        assertTrue(evaluator.evaluate(event(event, "ids", "brute_force", Map.of())).isEmpty());
        assertTrue(evaluator.evaluate(with(event, "rule_id", null)).isEmpty());
        for (String id : java.util.Arrays.asList(null, "", " ")) {
            assertTrue(evaluator.evaluate(new Event(id, event.timestamp(), event.source(), event.event_type(),
                event.severity(), event.title(), event.description(), event.details())).isEmpty());
        }
    }

    @Test
    void representsMissingAndNullMetadataWithoutInventingRequiredFields() throws Exception {
        var event = fixture();
        var absent = event(event, "ids", "brute_force", Map.of("rule_id", "P004"));
        var nullable = new LinkedHashMap<String, Object>();
        nullable.put("rule_id", "P004");
        for (String field : List.of("attempts", "source_ip", "window_seconds", "first_attempt", "last_attempt")) {
            nullable.put(field, null);
        }
        var result = evaluator.evaluate(absent).orElseThrow();
        assertTrue(result.attempts().isEmpty());
        assertTrue(result.sourceIp().isEmpty());
        assertTrue(result.windowSeconds().isEmpty());
        assertTrue(result.firstAttempt().isEmpty());
        assertTrue(result.lastAttempt().isEmpty());
        assertTrue(result.issues().isEmpty());
        assertEquals(result, evaluator.evaluate(event(event, "ids", "brute_force", nullable)).orElseThrow());
    }

    @Test
    void interpretsWholeNumericCountsWithoutRoundingOrOverflow() throws Exception {
        var event = fixture();
        for (Number value : List.<Number>of(1, 12L, new BigDecimal("12.0"),
                new BigInteger("9223372036854775808"))) {
            var result = evaluator.evaluate(with(event, "attempts", value)).orElseThrow();
            assertEquals(new BigDecimal(value.toString()).toBigIntegerExact(), result.attempts().orElseThrow());
            assertTrue(result.issues().isEmpty());
        }
    }

    @Test
    void reportsUnusableCountsWithoutEchoingValuesOrTreatingThemAsAttempts() throws Exception {
        var event = fixture();
        for (Object value : List.of(0, -1, 1.5, true, "12", SECRET, List.of(12),
                Map.of("credential", SECRET), Double.NaN, Double.POSITIVE_INFINITY)) {
            var result = evaluator.evaluate(with(event, "attempts", value)).orElseThrow();
            assertTrue(result.attempts().isEmpty());
            assertEquals(List.of("attempts: must be a positive integer"), result.issues());
            assertFalse(result.toString().contains(SECRET));
            assertEquals(event.event_id(), result.eventId());
        }
    }

    @Test
    void reportsMalformedOptionalMetadataInStableOrder() throws Exception {
        var event = fixture();
        var details = new LinkedHashMap<>(event.details());
        details.put("last_attempt", true);
        details.put("window_seconds", -1);
        details.put("source_ip", Map.of("credential", SECRET));
        details.put("first_attempt", SECRET);
        var result = evaluator.evaluate(event(event, "ids", "brute_force", details)).orElseThrow();
        assertTrue(result.sourceIp().isEmpty());
        assertTrue(result.windowSeconds().isEmpty());
        assertTrue(result.firstAttempt().isEmpty());
        assertTrue(result.lastAttempt().isEmpty());
        assertEquals(List.of("source_ip: must be a non-blank string",
            "window_seconds: must be a non-negative integer",
            "first_attempt: must be a valid UTC timestamp ending in Z",
            "last_attempt: must be a valid UTC timestamp ending in Z"), result.issues());
        assertFalse(result.toString().contains(SECRET));
    }

    @Test
    void reportsInvalidUtcDatesAndReversedBurstTimesWithoutThrowing() throws Exception {
        var event = fixture();
        for (String value : List.of("2026-02-30T13:50:10Z", "2026-04-20T13:50:10+00:00", "not-a-date")) {
            var result = evaluator.evaluate(with(event, "first_attempt", value)).orElseThrow();
            assertTrue(result.firstAttempt().isEmpty());
            assertEquals(List.of("first_attempt: must be a valid UTC timestamp ending in Z"), result.issues());
        }
        var reversed = evaluator.evaluate(with(event, "first_attempt", "2026-04-20T13:52:00Z")).orElseThrow();
        assertTrue(reversed.firstAttempt().isPresent());
        assertTrue(reversed.lastAttempt().isPresent());
        assertEquals(List.of("first_attempt: must not be after last_attempt"), reversed.issues());
    }

    @Test
    void doesNotReapplyIdsThresholdOrLimitTheTotalBurstToItsWindow() throws Exception {
        var event = with(fixture(), "attempts", 1);
        event = with(event, "first_attempt", "2026-04-20T13:00:00Z");
        var result = evaluator.evaluate(event).orElseThrow();
        assertEquals(BigInteger.ONE, result.attempts().orElseThrow());
        assertEquals(BigInteger.valueOf(60), result.windowSeconds().orElseThrow());
        assertTrue(result.issues().isEmpty());
        // No undocumented minimum window: zero is a representable duration.
        assertEquals(BigInteger.ZERO,
            evaluator.evaluate(with(event, "window_seconds", 0)).orElseThrow().windowSeconds().orElseThrow());
    }

    @Test
    void repeatedEvaluationIsDeterministicAndNeverAddsCounts() throws Exception {
        var event = fixture();
        var first = evaluator.evaluate(event).orElseThrow();
        evaluator.evaluate(with(event, "attempts", 20));
        var repeated = evaluator.evaluate(event).orElseThrow();
        assertEquals(first, repeated);
        assertEquals(BigInteger.valueOf(12), repeated.attempts().orElseThrow());
    }

    @Test
    void preservesIdentityForTheCallerToDetectChangedResends() throws Exception {
        var event = fixture();
        var first = evaluator.evaluate(event).orElseThrow();
        var changed = evaluator.evaluate(with(event, "attempts", 15)).orElseThrow();
        assertEquals(first.source(), changed.source());
        assertEquals(first.eventId(), changed.eventId());
        assertEquals(BigInteger.valueOf(15), changed.attempts().orElseThrow());
        assertNotEquals(first, changed);
    }

    @Test
    void copiesOnlyRelevantDataAndDoesNotMutateTheEvent() throws Exception {
        var fixture = fixture();
        var details = new LinkedHashMap<>(fixture.details());
        for (String field : List.of("credential", "password", "token", "service")) details.put(field, SECRET);
        details.put("usernames", List.of(SECRET));
        var event = new Event(fixture.event_id(), fixture.timestamp(), "ids", "brute_force",
            fixture.severity(), SECRET, SECRET, details);
        String before = JsonMapper.builder().build().writeValueAsString(event);
        var result = evaluator.evaluate(event).orElseThrow();
        assertFalse(result.toString().contains(SECRET));
        assertEquals(before, JsonMapper.builder().build().writeValueAsString(event));
        details.put("attempts", 999);
        assertEquals(BigInteger.valueOf(12), result.attempts().orElseThrow());
        assertThrows(UnsupportedOperationException.class, () -> result.issues().add(SECRET));
    }

    private Event fixture() throws Exception {
        try (var input = getClass().getResourceAsStream("/ids/p004.json")) {
            return JsonMapper.builder().build().readValue(input, Event.class);
        }
    }

    private Event with(Event event, String field, Object value) {
        var details = new LinkedHashMap<>(event.details());
        details.put(field, value);
        return event(event, event.source(), event.event_type(), details);
    }

    private Event event(Event original, String source, String type, Map<String, Object> details) {
        return new Event(original.event_id(), original.timestamp(), source, type,
            original.severity(), original.title(), original.description(), details);
    }
}
