package com.urjc.ciberurjc.siem.services;
import com.ciberurjc.siem.models.Event;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class EventService {

    private static final Logger logger = LoggerFactory.getLogger(EventService.class);

    public void processIncomingEvent(Event event) {
        // Registro por consola del evento recibido (Mock Ingesta)
        logger.info("=========================================");
        logger.info("[MOCK INGESTA] Evento recibido correctamente");
        logger.info("ID: {} | Módulo: {} | Severidad: {}", event.event_id(), event.source_module(), event.severity());
        logger.info("Tipo: {} | Origen IP: {}", event.event_type(), event.source_ip());
        logger.info("Descripción: {}", event.description());
        logger.info("Timestamp: {}", event.timestamp());
        logger.info("=========================================");
    }
}