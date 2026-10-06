package com.urjc.ciberurjc.siem.controller;
import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.services.EventService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/events")
public class EventController {

    private final EventService eventService;

    public EventController(EventService eventService) {
        this.eventService = eventService;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> receiveEvent(@RequestBody Event event) {
        // Validación básica de campos obligatorios según la HU03
        if (event.event_id() == null || event.source_module() == null || 
            event.severity() == null || event.event_type() == null || 
            event.source_ip() == null || event.description() == null || event.timestamp() == null) {
            
            return ResponseEntity.badRequest().body(Map.of(
                "status", "error",
                "message", "Faltan campos obligatorios en el contrato de ingesta"
            ));
        }

        // Procesar / Imprimir evento por consola
        eventService.processIncomingEvent(event);

        // Respuesta 200 OK exacta con el event_id
        return ResponseEntity.ok(Map.of(
            "status", "success",
            "message", "Evento recibido correctamente (Mock)",
            "event_id", event.event_id()
        ));
    }
}