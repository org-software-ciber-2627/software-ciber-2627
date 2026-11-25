package com.honeypot.honeypot.repository;

import com.honeypot.honeypot.model.RechazoResumen;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RechazoResumenRepository extends JpaRepository<RechazoResumen, Long> {

    Optional<RechazoResumen> findByIpAndMinutoAndServicio(String ip, Instant minuto, String servicio);

    List<RechazoResumen> findByIpOrderByMinutoAsc(String ip);
}
