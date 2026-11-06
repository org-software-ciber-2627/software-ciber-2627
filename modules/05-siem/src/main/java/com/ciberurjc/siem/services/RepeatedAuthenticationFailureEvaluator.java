package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.models.RepeatedAuthenticationFailure;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Interprets finalized, already aggregated IDS detections. No thresholds, counters,
 * storage or publication: the caller owns idempotency using (source, eventId).
 */
@Component
public class RepeatedAuthenticationFailureEvaluator {
    /**
     * Empty means this event cannot be identified as P004. A present result may
     * have absent metadata or issues; recognition is not proof that all data is usable.
     * Common Event validation remains the responsibility of the existing ingress.
     */
    public Optional<RepeatedAuthenticationFailure> evaluate(Event event) {
        if (event == null || !"ids".equals(event.source()) || !"brute_force".equals(event.event_type())
                || event.details() == null || !"P004".equals(event.details().get("rule_id"))
                || event.event_id() == null || event.event_id().isBlank()) {
            return Optional.empty();
        }

        var details = event.details();
        var issues = new ArrayList<String>();
        var attempts = integer(details, "attempts", true, issues);
        var sourceIp = text(details, "source_ip", issues);
        var window = integer(details, "window_seconds", false, issues);
        var first = instant(details, "first_attempt", issues);
        var last = instant(details, "last_attempt", issues);
        if (first.isPresent() && last.isPresent() && first.get().isAfter(last.get())) {
            issues.add("first_attempt: must not be after last_attempt");
        }

        // A burst can last longer than window_seconds; IDS has already evaluated its rule.
        return Optional.of(new RepeatedAuthenticationFailure(event.source(), event.event_id(),
            attempts, sourceIp, window, first, last, issues));
    }

    private Optional<BigInteger> integer(Map<String, Object> details, String field,
            boolean positive, List<String> issues) {
        Object value = details.get(field);
        if (value == null) return Optional.empty();
        if (value instanceof Number number) {
            try {
                // Exact conversion: no rounding, string/boolean coercion or fixed-width overflow.
                var integer = new BigDecimal(number.toString()).toBigIntegerExact();
                if (integer.signum() > 0 || (!positive && integer.signum() == 0)) {
                    return Optional.of(integer);
                }
            } catch (NumberFormatException | ArithmeticException exception) {
                // Report only a fixed field name and reason, never the rejected value.
            }
        }
        issues.add(field + (positive ? ": must be a positive integer" : ": must be a non-negative integer"));
        return Optional.empty();
    }

    private Optional<String> text(Map<String, Object> details, String field, List<String> issues) {
        Object value = details.get(field);
        if (value == null) return Optional.empty();
        if (value instanceof String text && !text.isBlank()) return Optional.of(text);
        issues.add(field + ": must be a non-blank string");
        return Optional.empty();
    }

    private Optional<Instant> instant(Map<String, Object> details, String field, List<String> issues) {
        Object value = details.get(field);
        if (value == null) return Optional.empty();
        if (value instanceof String timestamp && timestamp.endsWith("Z")) {
            try {
                return Optional.of(Instant.parse(timestamp));
            } catch (DateTimeParseException exception) {
                // No timestamps or parser diagnostics are exposed in the result.
            }
        }
        issues.add(field + ": must be a valid UTC timestamp ending in Z");
        return Optional.empty();
    }
}
