package com.honeypot.honeypot.ssh;

import static org.assertj.core.api.Assertions.assertThat;

import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * HP-67 con la BD real: los intentos SSH suman para la fuerza bruta (HP-12).
 * Misma configuración que HoneypotApplicationTests para reutilizar el contexto
 * y no abrir dos veces los puertos del SSH y del FTP.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:honeypot-test;DB_CLOSE_DELAY=-1")
@ActiveProfiles("dev")
class SshAttemptRecorderIntegracionTest {

    @Autowired
    private SshAttemptRecorder recorder;

    @Autowired
    private LoginAttemptRepository repositorio;

    @Test
    void elSextoIntentoSshEsFuerzaBruta() {
        String ip = "198.51.100.30";
        Instant inicio = Instant.parse("2026-11-03T12:00:00Z");
        for (int i = 0; i < 6; i++) {
            recorder.onAttempt(new SshAttemptData(ip, 50000 + i, inicio.plusSeconds(i * 5L), "admin",
                    SshAttemptData.AuthMethod.PASSWORD, "clave" + i, null, "SSH-2.0-OpenSSH_9.6"));
        }

        List<String> etiquetas = repositorio.findAll().stream()
                .filter(intento -> ip.equals(intento.getSourceIp()))
                .sorted(Comparator.comparing(LoginAttempt::getOccurredAt))
                .map(LoginAttempt::getTipoAtaque)
                .toList();
        assertThat(etiquetas).containsExactly(null, null, null, null, null, "fuerza_bruta");
    }
}
