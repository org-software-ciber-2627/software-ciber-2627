package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.services.EventService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/events")
public class EventController {
    private final EventService eventService;

    public EventController(EventService eventService) {
        this.eventService = eventService;
    }

    @PostMapping(consumes = "application/json", produces = "application/json")
    public Map<String, String> receiveEvent(@Valid @RequestBody Event event) {
        eventService.processIncomingEvent(event);
        return Map.of(
            "status", "success",
            "message", "Event received successfully (mock)",
            "event_id", event.event_id()
        );
    }
}
