package com.honeypot.honeypot.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.honeypot.honeypot.model.RechazoResumen;
import com.honeypot.honeypot.repository.RechazoResumenRepository;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * HP-88 con la BD H2: resumen de peticiones rechazadas por IP y minuto.
 * Misma configuración que HoneypotApplicationTests para reutilizar el contexto
 * y no abrir dos veces los puertos del SSH y del FTP.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:honeypot-test;DB_CLOSE_DELAY=-1")
@ActiveProfiles("dev")
class RechazoResumenServiceIntegracionTest {

    @Autowired
    private RechazoResumenService servicio;

    @Autowired
    private RechazoResumenRepository repositorio;

    // Tres rechazos de la misma IP en el mismo minuto: una sola fila con 3
    @Test
    void variosRechazosEnElMismoMinutoSonUnSoloRegistro() {
        String ip = "198.51.100.40";
        servicio.registrarRechazo(ip, "honeypot-web", Instant.parse("2026-11-09T12:00:05Z"));
        servicio.registrarRechazo(ip, "honeypot-web", Instant.parse("2026-11-09T12:00:30Z"));
        servicio.registrarRechazo(ip, "honeypot-web", Instant.parse("2026-11-09T12:00:59Z"));

        List<RechazoResumen> filas = repositorio.findByIpOrderByMinutoAsc(ip);
        assertThat(filas).hasSize(1);
        assertThat(filas.get(0).getMinuto()).isEqualTo(Instant.parse("2026-11-09T12:00:00Z"));
        assertThat(filas.get(0).getServicio()).isEqualTo("honeypot-web");
        assertThat(filas.get(0).getRechazos()).isEqualTo(3);
    }

    // Al cambiar de minuto se empieza otra fila
    @Test
    void otroMinutoEsOtroRegistro() {
        String ip = "198.51.100.41";
        servicio.registrarRechazo(ip, "honeypot-web", Instant.parse("2026-11-09T12:00:50Z"));
        servicio.registrarRechazo(ip, "honeypot-web", Instant.parse("2026-11-09T12:01:10Z"));

        List<RechazoResumen> filas = repositorio.findByIpOrderByMinutoAsc(ip);
        assertThat(filas).hasSize(2);
        assertThat(filas).extracting(RechazoResumen::getRechazos).containsExactly(1, 1);
    }
}
