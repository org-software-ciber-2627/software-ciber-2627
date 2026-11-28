package com.honeypot.honeypot.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.util.Comparator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

// HP-94: credenciales por defecto en el FTP, con la lista real de application.properties y la BD H2.
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:honeypot-test;DB_CLOSE_DELAY=-1")
@ActiveProfiles("dev")
class FtpCredencialesPorDefectoIntegracionTest {

    @Autowired
    private FtpEventService ftpEventService;

    @Autowired
    private LoginAttemptRepository repositorio;

    @Test
    void userYPassDeLaListaSeEtiquetanComoCredencialesPorDefecto() {
        String ip = "198.51.100.40";

        ftpEventService.registrarComando(ip, "USER", "admin", null);
        ftpEventService.registrarComando(ip, "PASS", "admin", "admin");

        LoginAttempt pass = ultimoPass(ip);
        assertThat(pass.getTipoAtaque()).isEqualTo(ClasificadorAtaquesService.CREDENCIALES_POR_DEFECTO);
        assertThat(pass.getUsername()).isEqualTo("admin");
    }

    @Test
    void unaParejaQueNoEstaEnLaListaNoSeEtiqueta() {
        String ip = "198.51.100.41";

        ftpEventService.registrarComando(ip, "USER", "admin", null);
        ftpEventService.registrarComando(ip, "PASS", "noEstaEnLaLista", "admin");

        assertThat(ultimoPass(ip).getTipoAtaque()).isNull();
    }

    @Test
    void siAdemasEsFuerzaBrutaGanaFuerzaBruta() {
        String ip = "198.51.100.42";

        // Cinco contraseñas que no están en la lista: todavía no es fuerza bruta
        for (int i = 0; i < 5; i++) {
            ftpEventService.registrarComando(ip, "PASS", "clave" + i, "admin");
        }
        // La sexta es de la lista, pero ya supera el umbral
        ftpEventService.registrarComando(ip, "PASS", "admin", "admin");

        assertThat(ultimoPass(ip).getTipoAtaque()).isEqualTo(ClasificadorAtaquesService.FUERZA_BRUTA);
    }

    @Test
    void unPassSinUserPrevioNoSeEtiquetaComoCredencialPorDefecto() {
        String ip = "198.51.100.43";

        ftpEventService.registrarComando(ip, "PASS", "admin", null);

        LoginAttempt pass = ultimoPass(ip);
        assertThat(pass.getTipoAtaque()).isNull();
        assertThat(pass.getCredentialAttempt()).isNotNull();
    }

    /** El último PASS guardado para esa IP. */
    private LoginAttempt ultimoPass(String ip) {
        return repositorio.findAll().stream()
                .filter(intento -> ip.equals(intento.getSourceIp()))
                .filter(intento -> intento.getCredentialAttempt() != null)
                .max(Comparator.comparing(LoginAttempt::getId))
                .orElseThrow();
    }
}