package com.ciberurjc.siem.models;

import java.util.List;

public record EventHistoryResponse(List<Event> events, Long next_offset, String next) {
    public EventHistoryResponse(List<Event> events, Long next_offset) {
        this(events, next_offset, null);
    }

    public EventHistoryResponse {
        events = List.copyOf(events);
    }
}
