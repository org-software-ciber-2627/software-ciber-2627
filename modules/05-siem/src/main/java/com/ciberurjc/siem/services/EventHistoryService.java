package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.models.EventHistoryQuery;
import com.ciberurjc.siem.models.EventHistoryResponse;
import com.ciberurjc.siem.repositories.EventRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class EventHistoryService {
    private final ObjectProvider<EventRepository> repositories;

    public EventHistoryService(ObjectProvider<EventRepository> repositories) {
        this.repositories = repositories;
    }

    public EventHistoryResponse findPage(EventHistoryQuery query) {
        EventRepository repository = repositories.getIfAvailable();
        if (repository == null) throw new EventStorageUnavailableException();
        List<Event> rows;
        try {
            rows = repository.findPage(query.limit() + 1, query.offset());
        } catch (DataAccessResourceFailureException | TransientDataAccessResourceException | QueryTimeoutException exception) {
            throw new EventStorageUnavailableException();
        }
        boolean hasMore = rows.size() > query.limit();
        int returnedSize = Math.min(rows.size(), query.limit());
        Long nextOffset = hasMore ? Math.addExact(query.offset(), query.limit()) : null;
        return new EventHistoryResponse(rows.subList(0, returnedSize), nextOffset);
    }
}
