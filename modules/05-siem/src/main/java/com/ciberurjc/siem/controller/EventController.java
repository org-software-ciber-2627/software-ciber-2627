package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.security.AccessPolicy;
import com.ciberurjc.siem.security.AuthenticatedIdentity;
import com.ciberurjc.siem.services.EventService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/events")
public class EventController {
    private final EventService eventService;
    private final AccessPolicy accessPolicy;

    public EventController(EventService eventService, AccessPolicy accessPolicy) {
        this.eventService = eventService;
        this.accessPolicy = accessPolicy;
    }

    @PostMapping(consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> receiveEvent(@Valid @RequestBody Event event,
                                          HttpServletRequest request) {
        // SEM-142: cada cuenta productora solo publica su propio source. Se comprueba antes de guardar.
        Object attribute = request.getAttribute(AuthenticatedIdentity.REQUEST_ATTRIBUTE);
        AuthenticatedIdentity identity = attribute instanceof AuthenticatedIdentity id ? id : null;
        if (!accessPolicy.canPublish(identity, event.source())) {
            return ResponseEntity.status(403)
                    .cacheControl(CacheControl.noStore())
                    .body(Map.of("error", Map.of(
                            "code", "SOURCE_MISMATCH",
                            "message", "The event source does not match the authenticated account")));
        }

        eventService.processIncomingEvent(event);
        return ResponseEntity.ok(Map.of(
            "status", "success",
            "message", "Event stored successfully",
            "event_id", event.event_id()
        ));
    }
}
