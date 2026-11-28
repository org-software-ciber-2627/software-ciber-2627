package com.honeypot.honeypot.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Criterios de HP-12 probados con la base de datos de verdad (H2 en memoria).
 *
 * Usa EXACTAMENTE la misma configuración que HoneypotApplicationTests para que Spring
 * reutilice el mismo contexto. Si se crease otro, el SSH (2222) y el FTP (2121)
 * intentarían abrir sus puertos dos veces y la prueba fallaría.
 * Cada prueba usa una IP distinta para no mezclarse con las demás.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:honeypot-test;DB_CLOSE_DELAY=-1")
@ActiveProfiles("dev")
class FuerzaBrutaIntegracionTest {

    private static final Instant INICIO = Instant.parse("2026-10-27T12:00:00Z");

    @Autowired
    private ClasificadorAtaquesService clasificador;

    @Autowired
    private LoginAttemptRepository repositorio;

    @Autowired
    private FtpEventService ftpEventService;

    @Test
    void cincoIntentosEnUnMinutoNoSonFuerzaBruta() {
        List<String> etiquetas = registrarVarios("198.51.100.1", 5, 10);

        assertThat(etiquetas).containsOnlyNulls();
    }

    @Test
    void elSextoIntentoEsFuerzaBrutaYLosAnterioresNoCambian() {
        String ip = "198.51.100.2";

        List<String> etiquetas = registrarVarios(ip, 6, 10);

        assertThat(etiquetas).containsExactly(null, null, null, null, null, ClasificadorAtaquesService.FUERZA_BRUTA);
        // En la BD, los cinco primeros siguen sin etiqueta: no se reetiquetan
        assertThat(etiquetasGuardadas(ip)).containsExactly(null, null, null, null, null, "fuerza_bruta");
    }

    @Test
    void seisIntentosSeparadosMasDeUnMinutoNoSonFuerzaBruta() {
        // Uno cada 13 segundos: el sexto llega a los 65 s y solo tiene 4 intentos en su último minuto
        List<String> etiquetas = registrarVarios("198.51.100.3", 6, 13);

        assertThat(etiquetas).containsOnlyNulls();
    }

    @Test
    void enElFtpSoloCuentanLosComandosPass() {
        String ip = "198.51.100.4";

        // Tres logins FTP con un LIST cada uno: 9 filas en la BD, pero solo 3 contraseñas
        loginFtp(ip, 3);
        assertThat(clasificador.clasificar(ip, Instant.now(), null, null)).isNull();

        // Tres logins más: el sexto PASS sí es fuerza bruta
        loginFtp(ip, 3);
        List<String> etiquetasPass = repositorio.findAll().stream()
                .filter(intento -> ip.equals(intento.getSourceIp()))
                .filter(intento -> intento.getCredentialAttempt() != null)
                .sorted(Comparator.comparing(LoginAttempt::getId))
                .map(LoginAttempt::getTipoAtaque)
                .toList();
        assertThat(etiquetasPass).containsExactly(null, null, null, null, null, "fuerza_bruta");
    }

    /** Registra intentos con contraseña de una IP, separados unos segundos, igual que el controlador. */
    private List<String> registrarVarios(String ip, int cuantos, int segundosEntreIntentos) {
        List<String> etiquetas = new ArrayList<>();
        for (int i = 0; i < cuantos; i++) {
            Instant momento = INICIO.plusSeconds((long) i * segundosEntreIntentos);
            LoginAttempt intento = new LoginAttempt();
            intento.setSourceIp(ip);
            intento.setOccurredAt(momento);
            intento.setServiceAttacked("honeypot-web");
            intento.setUsername("admin");
            intento.setCredentialAttempt("clave" + i);
            intento.setTipoAtaque(clasificador.clasificar(ip, momento, intento.getUsername(), intento.getCredentialAttempt()));
            repositorio.save(intento);
            etiquetas.add(intento.getTipoAtaque());
        }
        return etiquetas;
    }

    private List<String> etiquetasGuardadas(String ip) {
        return repositorio.findAll().stream()
                .filter(intento -> ip.equals(intento.getSourceIp()))
                .sorted(Comparator.comparing(LoginAttempt::getOccurredAt))
                .map(LoginAttempt::getTipoAtaque)
                .toList();
    }

    private void loginFtp(String ip, int veces) {
        for (int i = 0; i < veces; i++) {
            ftpEventService.registrarComando(ip, "USER", "admin");
            ftpEventService.registrarComando(ip, "PASS", "clave" + i);
            ftpEventService.registrarComando(ip, "LIST", null);
        }
    }
}
