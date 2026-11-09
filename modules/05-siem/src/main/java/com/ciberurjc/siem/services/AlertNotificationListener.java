
package com.ciberurjc.siem.services;

import com.ciberurjc.siem.models.AlertNotification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class AlertNotificationListener {

    private static final Logger logger =
        LoggerFactory.getLogger(AlertNotificationListener.class);

    @EventListener
    public void onAlert(AlertNotification notification) {
        logger.info(
            "New SIEM alert emitted: id={}, severity={}",
            notification.alert().get("alert_id"),
            notification.alert().get("severity")
        );
    }
}
