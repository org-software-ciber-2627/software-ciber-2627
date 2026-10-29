package com.ciberurjc.siem.repositories;

import com.ciberurjc.siem.models.Event;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.core.JdbcTemplate;
import javax.sql.DataSource;
import org.springframework.stereotype.Repository;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectReader;

import java.sql.SQLException;
import java.sql.ResultSet;
import java.util.List;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

@Repository
@Profile("persistence")
public class PostgresEventRepository implements EventRepository {
    // ISO year -4712 is 4713 BC. Reject dates outside PostgreSQL's finite timestamp range.
    private static final Instant MIN_TIMESTAMP = Instant.parse("-4712-01-01T00:00:00Z");
    private static final Instant MAX_TIMESTAMP_EXCLUSIVE = Instant.parse("+294277-01-01T00:00:00Z");
    private final JdbcClient jdbc;
    private final JdbcClient historyJdbc;
    private final ObjectMapper mapper;
    private final ObjectReader detailsReader;

    public PostgresEventRepository(JdbcClient jdbc, ObjectMapper mapper, DataSource dataSource) {
        this.jdbc = jdbc;
        JdbcTemplate historyTemplate = new JdbcTemplate(dataSource);
        historyTemplate.setQueryTimeout(5);
        this.historyJdbc = JdbcClient.create(historyTemplate);
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
        for (String text : new String[]{event.event_id(), event.timestamp(), event.source(), event.event_type(),
                event.severity(), event.title(), event.description()}) {
            requireStorableText(text);
        }
        requireStorableJson(event.details());
        Instant instant = Instant.parse(event.timestamp());
        if (instant.isBefore(MIN_TIMESTAMP) || !instant.isBefore(MAX_TIMESTAMP_EXCLUSIVE)) {
            throw new IllegalArgumentException("Timestamp is outside the supported storage range");
        }
        OffsetDateTime occurredAt = instant.atOffset(ZoneOffset.UTC);
        String details = mapper.writeValueAsString(event.details());
        try {
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
        } catch (DataAccessException exception) {
            for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
                if (cause instanceof SQLException sqlException && sqlException.getSQLState() != null
                        && sqlException.getSQLState().startsWith("22")) {
                    // SQLSTATE class 22 is invalid data, not a storage availability failure.
                    throw new IllegalArgumentException("Event data cannot be represented in storage", exception);
                }
            }
            throw exception;
        }
    }

    private static void requireStorableJson(Object value) {
        if (value instanceof String text) {
            requireStorableText(text);
        } else if (value instanceof Map<?, ?> object) {
            object.forEach((key, child) -> {
                if (key instanceof String text) requireStorableText(text);
                requireStorableJson(child);
            });
        } else if (value instanceof Iterable<?> array) {
            array.forEach(PostgresEventRepository::requireStorableJson);
        }
    }

    private static void requireStorableText(String text) {
        if (text == null) return;
        for (int i = 0; i < text.length(); i++) {
            char character = text.charAt(i);
            if (character == 0) {
                throw new IllegalArgumentException("Event text cannot contain null characters");
            }
            if (Character.isHighSurrogate(character)) {
                if (i + 1 >= text.length() || !Character.isLowSurrogate(text.charAt(i + 1))) {
                    throw new IllegalArgumentException("Event text must contain valid Unicode");
                }
                i++;
            } else if (Character.isLowSurrogate(character)) {
                throw new IllegalArgumentException("Event text must contain valid Unicode");
            }
        }
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
            .query(this::mapEvent)
            .optional();
    }

    @Override
    public List<Event> findPage(int fetchLimit, long offset) {
        if (fetchLimit < 1 || fetchLimit > 501 || offset < 0) {
            throw new IllegalArgumentException("Invalid repository pagination parameters");
        }
        return historyJdbc.sql("""
            SELECT event_id, occurred_at, source, event_type, severity, title, description, details, original_timestamp
            FROM events
            ORDER BY occurred_at DESC, source ASC, event_id ASC
            LIMIT :fetchLimit OFFSET :offset
            """)
            .param("fetchLimit", fetchLimit)
            .param("offset", offset)
            .query(this::mapEvent)
            .list();
    }

    private Event mapEvent(ResultSet result, int rowNumber) throws SQLException {
        String timestamp = result.getString("original_timestamp");
        if (timestamp == null) {
            timestamp = result.getObject("occurred_at", OffsetDateTime.class).toInstant().toString();
        }
        Map<String, Object> details = detailsReader.readValue(result.getString("details"));
        return new Event(result.getString("event_id"), timestamp, result.getString("source"),
            result.getString("event_type"), result.getString("severity"), result.getString("title"),
            result.getString("description"), details);
    }

}
