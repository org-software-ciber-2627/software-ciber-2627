
package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.AlertNotification;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AlertService {

    private final ApplicationEventPublisher publisher;

    public AlertService(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    public void emitAlert(Map<String, Object> alert) {
        publisher.publishEvent(new AlertNotification(alert));
    }
}


