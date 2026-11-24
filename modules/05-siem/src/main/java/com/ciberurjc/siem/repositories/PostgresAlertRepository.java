package com.ciberurjc.siem.repositories;

import com.ciberurjc.siem.services.AlertRepository;
import com.ciberurjc.siem.services.AlertStorageUnavailableException;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectReader;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

@Repository
@Profile("persistence")
public class PostgresAlertRepository implements AlertRepository {
    private final JdbcClient jdbc;
    private final JdbcClient readJdbc;
    private final ObjectMapper mapper;
    private final ObjectReader alertReader;

    public PostgresAlertRepository(JdbcClient jdbc, ObjectMapper mapper, DataSource dataSource) {
        this.jdbc = jdbc;
        JdbcTemplate readTemplate = new JdbcTemplate(dataSource);
        readTemplate.setQueryTimeout(5);
        this.readJdbc = JdbcClient.create(readTemplate);
        this.mapper = mapper;
        this.alertReader = mapper.readerFor(new TypeReference<Map<String, Object>>() {})
            .with(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
        requireAlertsTable();
    }

    // SEM-146 D8: fail at startup instead of answering 503/500 on the first request.
    private void requireAlertsTable() {
        Boolean present = jdbc.sql("SELECT to_regclass('alerts') IS NOT NULL").query(Boolean.class).single();
        if (!Boolean.TRUE.equals(present)) {
            throw new IllegalStateException(
                "Table 'alerts' is missing: apply db/init/005-create-alerts.sql (see docs/sem67-persistence-guide.md)");
        }
    }

    @Override
    public SaveResult insertIfAbsent(Map<String, Object> alert) {
        int inserted = jdbc.sql("""
            INSERT INTO alerts (alert_id, source, event_id, alert)
            VALUES (:alertId, :source, :eventId, CAST(:alert AS jsonb))
            ON CONFLICT (source, event_id) DO NOTHING
            """)
            .param("alertId", alert.get("alert_id"))
            .param("source", alert.get("source"))
            .param("eventId", alert.get("event_id"))
            .param("alert", mapper.writeValueAsString(alert))
            .update();
        return inserted == 1 ? SaveResult.CREATED : SaveResult.UNCHANGED;
    }

    @Override
    public List<Map<String, Object>> findAll() {
        // Stable output only; SEM-68 does not guarantee an order.
        return read(() -> readJdbc.sql("SELECT alert FROM alerts ORDER BY created_at, alert_id")
            .query((result, row) -> parse(result.getString("alert")))
            .list());
    }

    @Override
    public Optional<Map<String, Object>> findById(String alertId) {
        return read(() -> readJdbc.sql("SELECT alert FROM alerts WHERE alert_id = :alertId")
            .param("alertId", alertId)
            .query((result, row) -> parse(result.getString("alert")))
            .optional());
    }

    private Map<String, Object> parse(String json) {
        return alertReader.readValue(json);
    }

    // Only availability failures become 503; schema or mapping errors stay 500.
    private static <T> T read(Supplier<T> query) {
        try {
            return query.get();
        } catch (DataAccessResourceFailureException | TransientDataAccessResourceException | QueryTimeoutException exception) {
            throw new AlertStorageUnavailableException(exception);
        }
    }
}
