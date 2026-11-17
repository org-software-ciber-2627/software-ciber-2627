package com.ciberurjc.siem;

import com.ciberurjc.siem.models.EventHistoryQuery;
import com.ciberurjc.siem.services.InvalidHistoryQueryException;
import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;
import static org.junit.jupiter.api.Assertions.*;

class EventHistoryQueryTests {
    @Test
    void defaultsAndExplicitValuesProduceTheSameQuery() {
        var parameters = new LinkedMultiValueMap<String, String>();
        assertEquals(new EventHistoryQuery(100, 0), EventHistoryQuery.from(parameters));
        parameters.add("limit", "100");
        parameters.add("offset", "0");
        assertEquals(new EventHistoryQuery(100, 0), EventHistoryQuery.from(parameters));
    }

    @Test
    void acceptsBoundariesWithoutOverflow() {
        for (int limit : new int[]{1, 500}) {
            var parameters = new LinkedMultiValueMap<String, String>();
            parameters.add("limit", Integer.toString(limit));
            parameters.add("offset", Long.toString(Long.MAX_VALUE - limit));
            var query = EventHistoryQuery.from(parameters);
            assertEquals(Long.MAX_VALUE, Math.addExact(query.offset(), query.limit()));
        }
    }

    @Test
    void rejectsMalformedOrExcessiveInputBeforeStorage() {
        for (String value : new String[]{"", " ", "-1", "+1", "1.5", "1e2", "NaN", "0 OR 1=1",
                "0;DROP TABLE events", "9223372036854775808", "00000000000000000000", "１２"}) {
            for (String name : new String[]{"limit", "offset"}) {
                var parameters = new LinkedMultiValueMap<String, String>();
                parameters.add(name, value);
                assertThrows(InvalidHistoryQueryException.class, () -> EventHistoryQuery.from(parameters), name + ": " + value);
            }
        }
    }

    @Test
    void rejectsDuplicatesUnknownNamesAndInvalidRanges() {
        var duplicate = new LinkedMultiValueMap<String, String>();
        duplicate.add("limit", "1");
        duplicate.add("limit", "2");
        assertThrows(InvalidHistoryQueryException.class, () -> EventHistoryQuery.from(duplicate));
        var unknown = new LinkedMultiValueMap<String, String>();
        unknown.add("order", "event_id DESC");
        assertThrows(InvalidHistoryQueryException.class, () -> EventHistoryQuery.from(unknown));
        for (int limit : new int[]{0, 501, Integer.MAX_VALUE}) {
            assertThrows(InvalidHistoryQueryException.class, () -> new EventHistoryQuery(limit, 0));
        }
        assertThrows(InvalidHistoryQueryException.class, () -> new EventHistoryQuery(100, -1));
        assertThrows(InvalidHistoryQueryException.class, () -> new EventHistoryQuery(100, Long.MAX_VALUE - 99));
    }
}
