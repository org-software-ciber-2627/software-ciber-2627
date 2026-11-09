package com.ciberurjc.siem.repositories;

import com.ciberurjc.siem.models.Event;
import java.util.Optional;
import java.util.List;

public interface EventRepository {
    enum SaveResult { STORED, REPLAY, CONFLICT }

    List<Event> findPage(int fetchLimit, long offset);

    void save(Event event);

    SaveResult saveIfAbsent(Event event);

    Optional<Event> findById(String source, String eventId);
}
