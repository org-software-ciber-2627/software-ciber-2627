package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.models.EventHistoryQuery;
import com.ciberurjc.siem.repositories.EventRepository;
import com.ciberurjc.siem.services.EventHistoryService;
import com.ciberurjc.siem.services.EventStorageUnavailableException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.dao.TransientDataAccessResourceException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class EventHistoryServiceTests {
    static Event event(String id) {
        return new Event(id, "2026-10-29T12:00:00.123456789Z", "scanner", "vulnerability_detected", "low",
                "History example", "History fixture", Map.of("nested", List.of(true, 42)));
    }

    static class FakeRepository implements EventRepository {
        List<Event> events = List.of();
        RuntimeException failure;
        int calls;
        int requestedLimit;
        long requestedOffset;

        public List<Event> findPage(int limit, long offset) {
            calls++;
            requestedLimit = limit;
            requestedOffset = offset;
            if (failure != null) throw failure;
            return events.stream().skip(offset).limit(limit).toList();
        }
        public void save(Event event) { throw new UnsupportedOperationException(); }
        public SaveResult saveIfAbsent(Event event) { throw new UnsupportedOperationException(); }
        public Optional<Event> findById(String source, String id) { throw new UnsupportedOperationException(); }
    }

    static EventHistoryService service(EventRepository repository) {
        var factory = new StaticListableBeanFactory();
        if (repository != null) factory.addBean("repository", repository);
        return new EventHistoryService(factory.getBeanProvider(EventRepository.class));
    }

    @Test
    void extraRowDetectsContinuationWithoutLosingTheNextEvent() {
        var repository = new FakeRepository();
        repository.events = List.of(event("first"), event("second"), event("third"));
        var history = service(repository);
        var first = history.findPage(new EventHistoryQuery(2, 0));
        assertEquals(repository.events.subList(0, 2), first.events());
        assertEquals(2L, first.next_offset());
        assertEquals(3, repository.requestedLimit);
        var next = history.findPage(new EventHistoryQuery(2, first.next_offset()));
        assertEquals(List.of(repository.events.get(2)), next.events());
        assertNull(next.next_offset());
        assertEquals(2, repository.requestedOffset);
    }

    @Test
    void emptyExactAndPastEndPagesHaveNoContinuation() {
        var repository = new FakeRepository();
        var history = service(repository);
        var empty = history.findPage(new EventHistoryQuery(1, 0));
        assertTrue(empty.events().isEmpty());
        assertNull(empty.next_offset());
        repository.events = List.of(event("one"));
        assertNull(history.findPage(new EventHistoryQuery(1, 0)).next_offset());
        assertTrue(history.findPage(new EventHistoryQuery(1, Long.MAX_VALUE - 1)).events().isEmpty());
    }

    @Test
    void unavailableProfileAndResourceFailuresDoNotReturnEmptySuccess() {
        assertThrows(EventStorageUnavailableException.class, () -> service(null).findPage(new EventHistoryQuery(100, 0)));
        var repository = new FakeRepository();
        for (RuntimeException failure : List.of(new DataAccessResourceFailureException("private-connection"),
                new TransientDataAccessResourceException("private-transient"), new QueryTimeoutException("private-timeout"))) {
            repository.failure = failure;
            assertThrows(EventStorageUnavailableException.class, () -> service(repository).findPage(new EventHistoryQuery(100, 0)));
        }
    }

    @Test
    void queryDefectsAreNotMisclassifiedAsTemporaryUnavailability() {
        var repository = new FakeRepository();
        var failure = new InvalidDataAccessResourceUsageException("private SQL defect");
        repository.failure = failure;
        assertSame(failure, assertThrows(InvalidDataAccessResourceUsageException.class,
                () -> service(repository).findPage(new EventHistoryQuery(100, 0))));
    }
}
