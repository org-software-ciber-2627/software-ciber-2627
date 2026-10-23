package com.ciberurjc.siem;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.repositories.EventRepository;
import com.ciberurjc.siem.services.EventService;
import com.ciberurjc.siem.services.EventStorageUnavailableException;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.dao.DataAccessResourceFailureException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class EventServiceLoggingTests {
    @Test
    void successfulWritesEscapeControlsWithoutChangingStoredEvent() {
        for (var result : List.of(EventRepository.SaveResult.STORED, EventRepository.SaveResult.REPLAY)) {
            verifyLog("id\r\nFORGED\t\u000b\f\u001b\u007f\u0085\u2028\u2029", result, false,
                "id\\u000d\\u000aFORGED\\u0009\\u000b\\u000c\\u001b\\u007f\\u0085\\u2028\\u2029");
        }
    }

    @Test
    void failedWritesEscapeControlsAndKeepPrivatePayloadOutOfLogs() {
        verifyLog("id\r\nFORGED\u0085\u2028", EventRepository.SaveResult.STORED, true,
            "id\\u000d\\u000aFORGED\\u0085\\u2028");
    }

    @Test
    void ordinaryUnicodeIdentifiersRemainReadable() {
        verifyLog("sensor-ñ-東京-001", EventRepository.SaveResult.STORED, false, "sensor-ñ-東京-001");
    }

    private void verifyLog(String id, EventRepository.SaveResult result, boolean fail, String safeId) {
        var input = new Event(id, "2026-10-23T12:00:00Z", "ids", "port_scan", "medium",
            "Private title marker", "Private description marker", Map.of("credential", "private-payload-marker"));
        var received = new ArrayList<Event>();
        EventRepository storage = new EventRepository() {
            public void save(Event event) { throw new UnsupportedOperationException(); }
            public Optional<Event> findById(String source, String eventId) { throw new UnsupportedOperationException(); }
            public SaveResult saveIfAbsent(Event event) {
                received.add(event);
                if (fail) throw new DataAccessResourceFailureException("private-db-error-marker");
                return result;
            }
        };
        var factory = new StaticListableBeanFactory();
        factory.addBean("repository", storage);
        var service = new EventService(factory.getBeanProvider(EventRepository.class));
        var logger = (Logger) LoggerFactory.getLogger(EventService.class);
        var appender = new ListAppender<ILoggingEvent>();
        appender.start();
        logger.addAppender(appender);
        try {
            if (fail) assertThrows(EventStorageUnavailableException.class, () -> service.processIncomingEvent(input));
            else service.processIncomingEvent(input);
            assertEquals(List.of(input), received);
            assertSame(input, received.getFirst());
            assertEquals(1, appender.list.size());
            String message = appender.list.getFirst().getFormattedMessage();
            assertEquals(fail ? "Event storage failed: id=" + safeId + ", source=ids"
                : "Event storage confirmed: id=" + safeId + ", source=ids, result=" + result, message);
            assertFalse(message.codePoints().anyMatch(c -> Character.isISOControl(c) || c == 0x2028 || c == 0x2029));
            assertFalse(message.contains("private-payload-marker"));
            assertFalse(message.contains("private-db-error-marker"));
            assertFalse(message.contains(input.title()));
            assertNull(appender.list.getFirst().getThrowableProxy());
        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }
    }
}
