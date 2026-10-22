package com.ciberurjc.siem.repositories;

import com.ciberurjc.siem.models.Event;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectReader;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

@Repository
@Profile("persistence")
public class PostgresEventRepository implements EventRepository {
    private final JdbcClient jdbc;
    private final ObjectMapper mapper;
    private final ObjectReader detailsReader;

    public PostgresEventRepository(JdbcClient jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.detailsReader = mapper.readerFor(new TypeReference<Map<String, Object>>() {})
            .with(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
    }

    @Override
    public void save(Event event) {
        insert(event, false);
    }

    @Override
    public SaveResult saveIfAbsent(Event event) {
        if (insert(event, true) == 1) {
            return SaveResult.STORED;
        }
        // A separate statement sees the winner after a concurrent insert commits.
        boolean matches = jdbc.sql("""
            SELECT CASE WHEN original_timestamp IS NULL THEN occurred_at = :occurredAt
                        ELSE original_timestamp = :timestamp END
                AND event_type = :eventType AND severity = :severity
                AND title = :title AND description = :description AND details = CAST(:details AS jsonb)
            FROM events WHERE source = :source AND event_id = :eventId
            """)
            .param("source", event.source()).param("eventId", event.event_id())
            .param("timestamp", event.timestamp()).param("eventType", event.event_type())
            .param("occurredAt", Instant.parse(event.timestamp()).atOffset(ZoneOffset.UTC))
            .param("severity", event.severity()).param("title", event.title())
            .param("description", event.description()).param("details", mapper.writeValueAsString(event.details()))
            .query(Boolean.class).single();
        return matches ? SaveResult.REPLAY : SaveResult.CONFLICT;
    }

    private int insert(Event event, boolean ignoreDuplicate) {
        OffsetDateTime occurredAt = Instant.parse(event.timestamp()).atOffset(ZoneOffset.UTC);
        String details = mapper.writeValueAsString(event.details());
        return jdbc.sql("""
            INSERT INTO events (
                event_id, occurred_at, source, event_type, severity, title, description, details, original_timestamp
            ) VALUES (
                :eventId, :occurredAt, :source, :eventType, :severity, :title, :description,
                CAST(:details AS jsonb), :originalTimestamp
            )
            """ + (ignoreDuplicate ? " ON CONFLICT (source, event_id) DO NOTHING" : ""))
            .param("eventId", event.event_id())
            .param("occurredAt", occurredAt)
            .param("source", event.source())
            .param("eventType", event.event_type())
            .param("severity", event.severity())
            .param("title", event.title())
            .param("description", event.description())
            .param("details", details)
            .param("originalTimestamp", event.timestamp())
            .update();
    }

    @Override
    public Optional<Event> findById(String source, String eventId) {
        return jdbc.sql("""
            SELECT event_id, occurred_at, source, event_type, severity, title, description, details, original_timestamp
            FROM events
            WHERE source = :source AND event_id = :eventId
            """)
            .param("source", source)
            .param("eventId", eventId)
            .query((result, rowNumber) -> {
                String timestamp = result.getString("original_timestamp");
                if (timestamp == null) {
                    timestamp = result.getObject("occurred_at", OffsetDateTime.class).toInstant().toString();
                }
                Map<String, Object> details = detailsReader.readValue(result.getString("details"));
                return new Event(result.getString("event_id"), timestamp, result.getString("source"),
                    result.getString("event_type"), result.getString("severity"), result.getString("title"),
                    result.getString("description"), details);
            })
            .optional();
    }
}
