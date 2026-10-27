package com.ciberurjc.siem.repositories;
import com.ciberurjc.siem.models.Alert;
import java.util.Optional;

public interface AlertRepository {
    Optional<Alert> findById(String AlertId);
}