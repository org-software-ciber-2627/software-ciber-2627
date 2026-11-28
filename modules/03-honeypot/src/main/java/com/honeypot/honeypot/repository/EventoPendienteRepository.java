package com.honeypot.honeypot.repository;

import com.honeypot.honeypot.model.EventoPendiente;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EventoPendienteRepository extends JpaRepository<EventoPendiente, Long> {

    /**
     * Los pendientes más antiguos, en el orden en que se guardaron (HP-22).
     * De 100 en 100 para no cargarlos todos si el SIEM lleva mucho tiempo caído.
     */
    List<EventoPendiente> findTop100ByOrderByIdAsc();
}
