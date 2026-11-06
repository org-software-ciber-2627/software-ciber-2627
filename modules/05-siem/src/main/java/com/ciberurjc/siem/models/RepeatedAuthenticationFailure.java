package com.ciberurjc.siem.models;

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** A snapshot of an IDS P004 detection, not an alert or a new count of attempts. */
public record RepeatedAuthenticationFailure(
    String source,
    String eventId,
    Optional<BigInteger> attempts,
    Optional<String> sourceIp,
    Optional<BigInteger> windowSeconds,
    Optional<Instant> firstAttempt,
    Optional<Instant> lastAttempt,
    List<String> issues
) {
    public RepeatedAuthenticationFailure {
        issues = List.copyOf(issues);
    }
}
