package com.ciberurjc.siem.repositories;

import com.ciberurjc.siem.models.Event;
import java.util.Optional;

public interface EventRepository {
    enum SaveResult { STORED, REPLAY, CONFLICT }

    void save(Event event);

    SaveResult saveIfAbsent(Event event);

    Optional<Event> findById(String source, String eventId);
}
