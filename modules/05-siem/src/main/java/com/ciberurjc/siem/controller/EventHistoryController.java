package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.models.EventHistoryQuery;
import com.ciberurjc.siem.models.EventHistoryResponse;
import com.ciberurjc.siem.services.EventHistoryService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/events")
public class EventHistoryController {
    private final EventHistoryService history;

    public EventHistoryController(EventHistoryService history) {
        this.history = history;
    }

    @GetMapping(produces = "application/json")
    public ResponseEntity<EventHistoryResponse> listEvents(@RequestParam MultiValueMap<String, String> parameters,
            HttpServletRequest request) {
        EventHistoryQuery query = EventHistoryQuery.from(parameters);
        EventHistoryResponse page = history.findPage(query);
        String next = page.next_offset() == null ? null
                : request.getContextPath() + "/events?limit=" + query.limit() + "&offset=" + page.next_offset();
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(new EventHistoryResponse(page.events(), page.next_offset(), next));
    }
}
