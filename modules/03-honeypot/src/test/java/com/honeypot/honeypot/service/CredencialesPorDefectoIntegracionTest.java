package com.honeypot.honeypot.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * HP-83 con la configuración real (application.properties) y la BD H2.
 * Misma configuración que HoneypotApplicationTests para reutilizar el contexto
 * y no abrir dos veces los puertos del SSH y del FTP.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:honeypot-test;DB_CLOSE_DELAY=-1")
@ActiveProfiles("dev")
class CredencialesPorDefectoIntegracionTest {

    @Autowired
    private ClasificadorAtaquesService clasificador;

    @Autowired
    private LoginAttemptRepository repositorio;

    @Test
    void unIntentoConCredencialDeLaListaSeGuardaComoCredencialesPorDefecto() {
        LoginAttempt intento = new LoginAttempt();
        intento.setSourceIp("198.51.100.20");
        intento.setOccurredAt(Instant.parse("2026-10-30T12:00:00Z"));
        intento.setServiceAttacked("honeypot-web");
        intento.setUsername("root");
        intento.setCredentialAttempt("toor");
        intento.setTipoAtaque(clasificador.clasificar(intento.getSourceIp(), intento.getOccurredAt(),
                intento.getUsername(), intento.getCredentialAttempt()));

        LoginAttempt guardado = repositorio.save(intento);

        assertThat(repositorio.findById(guardado.getId()).orElseThrow().getTipoAtaque())
                .isEqualTo(ClasificadorAtaquesService.CREDENCIALES_POR_DEFECTO);
    }
}
