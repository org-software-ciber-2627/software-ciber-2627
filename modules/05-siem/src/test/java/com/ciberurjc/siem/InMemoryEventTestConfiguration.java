package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.repositories.EventRepository;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@TestConfiguration(proxyBeanMethods = false)
class InMemoryEventTestConfiguration {
    @Bean
    EventRepository testEventRepository() {
        return new EventRepository() {
            private final Map<List<String>, Event> events = new ConcurrentHashMap<>();

            @Override
            public SaveResult saveIfAbsent(Event event) {
                var existing = events.putIfAbsent(List.of(event.source(), event.event_id()), event);
                if (existing == null) {
                    return SaveResult.STORED;
                }
                return existing.equals(event) ? SaveResult.REPLAY : SaveResult.CONFLICT;
            }

            @Override
            public Optional<Event> findById(String source, String eventId) {
                return Optional.ofNullable(events.get(List.of(source, eventId)));
            }

            @Override
            public void save(Event event) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<Event> findPage(int fetchLimit, long offset) {
                throw new UnsupportedOperationException();
            }
        };
    }
}
