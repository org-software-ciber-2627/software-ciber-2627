package com.ciberurjc.siem;

import com.ciberurjc.siem.repositories.PostgresEventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.AbstractDataSource;
import tools.jackson.databind.json.JsonMapper;
import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

// Verifies the actual Spring JDBC path using recording JDBC objects, not a database.
class EventHistoryJdbcTests {
    static class RecordingDataSource extends AbstractDataSource {
        String sql;
        int timeout;
        int executions;
        int closedConnections;
        int closedStatements;
        int closedResults;
        final Map<Integer, Object> parameters = new HashMap<>();
        final List<Map<String, Object>> rows = new ArrayList<>();

        @SuppressWarnings("unchecked")
        static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
            return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
        }

        public Connection getConnection(String username, String password) { return getConnection(); }

        public Connection getConnection() {
            return proxy(Connection.class, (connection, method, args) -> switch (method.getName()) {
                case "prepareStatement" -> { sql = (String) args[0]; yield statement(); }
                case "close" -> { closedConnections++; yield null; }
                case "isClosed" -> false;
                case "getAutoCommit" -> true;
                default -> throw new UnsupportedOperationException(method.getName());
            });
        }

        PreparedStatement statement() {
            return proxy(PreparedStatement.class, (statement, method, args) -> switch (method.getName()) {
                case "setQueryTimeout" -> { timeout = (Integer) args[0]; yield null; }
                case "setObject", "setInt", "setLong", "setString" -> { parameters.put((Integer) args[0], args[1]); yield null; }
                case "executeQuery" -> { executions++; yield result(); }
                case "getWarnings" -> null;
                case "close" -> { closedStatements++; yield null; }
                default -> throw new UnsupportedOperationException(method.getName());
            });
        }

        ResultSet result() {
            int[] cursor = {-1};
            return proxy(ResultSet.class, (result, method, args) -> switch (method.getName()) {
                case "next" -> ++cursor[0] < rows.size();
                case "getString" -> rows.get(cursor[0]).get((String) args[0]);
                case "getObject" -> OffsetDateTime.parse((String) rows.get(cursor[0]).get((String) args[0]));
                case "close" -> { closedResults++; yield null; }
                default -> throw new UnsupportedOperationException(method.getName());
            });
        }
    }

    PostgresEventRepository repository(RecordingDataSource dataSource) {
        return new PostgresEventRepository(JdbcClient.create(dataSource), JsonMapper.builder().build(), dataSource);
    }

    @Test
    void bindsPaginationInPreparedSqlAndClosesJdbcResources() {
        var dataSource = new RecordingDataSource();
        assertTrue(repository(dataSource).findPage(501, 23).isEmpty());
        String sql = dataSource.sql.replaceAll("\\s+", " ").trim();
        assertTrue(sql.endsWith("ORDER BY occurred_at DESC, source ASC, event_id ASC LIMIT ? OFFSET ?"), sql);
        assertEquals(Map.of(1, 501, 2, 23L), dataSource.parameters);
        assertEquals(5, dataSource.timeout);
        assertEquals(1, dataSource.executions);
        assertEquals(1, dataSource.closedResults);
        assertEquals(1, dataSource.closedStatements);
        assertEquals(1, dataSource.closedConnections);
    }

    @Test
    void invalidDirectCallsCannotExecuteAnUnboundedQuery() {
        var dataSource = new RecordingDataSource();
        var repository = repository(dataSource);
        for (int limit : new int[]{0, -1, 502, Integer.MAX_VALUE}) {
            assertThrows(IllegalArgumentException.class, () -> repository.findPage(limit, 0));
        }
        assertThrows(IllegalArgumentException.class, () -> repository.findPage(1, -1));
        assertEquals(0, dataSource.executions);
    }

    @Test
    void sharedMapperPreservesJsonNumbersAndLegacyTimestampFallback() {
        var dataSource = new RecordingDataSource();
        var row = new HashMap<String, Object>();
        row.put("event_id", "history-id");
        row.put("source", "scanner");
        row.put("event_type", "vulnerability_detected");
        row.put("severity", "low");
        row.put("title", "History example");
        row.put("description", "Mapping fixture");
        row.put("occurred_at", "2026-10-29T12:00:00Z");
        row.put("original_timestamp", "2026-10-29T12:00:00.123456789Z");
        row.put("details", "{\"nested\":[null,true,42],\"decimal\":1234567890.12345678901234567890}");
        dataSource.rows.add(row);
        var repository = repository(dataSource);
        var event = repository.findPage(1, 0).getFirst();
        assertEquals(row.get("original_timestamp"), event.timestamp());
        assertEquals(new BigDecimal("1234567890.12345678901234567890"), event.details().get("decimal"));
        assertEquals(java.util.Arrays.asList(null, true, 42), event.details().get("nested"));
        row.remove("original_timestamp");
        assertEquals("2026-10-29T12:00:00Z", repository.findPage(1, 0).getFirst().timestamp());
        assertEquals("2026-10-29T12:00:00Z", repository.findById("scanner", "history-id").orElseThrow().timestamp());
    }
}
