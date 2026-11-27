package com.honeypot.honeypot.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:h2:mem:honeypot-scan-test;DB_CLOSE_DELAY=-1",
                "honeypot.ftp.port=2122",
                "honeypot.ssh.port=2223"
        })
@ActiveProfiles("dev")
class DetectorEscaneoServiceTest {

    private static final int FTP_PORT = 2122;
    private static final int SSH_PORT = 2223;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    private SiemSenderService siemSenderService;

    @Test
    void escaneoTcpEnDosServiciosSeGuardaYSeEnviaAlSiemComoEscaneo() throws Exception {
        when(siemSenderService.enviarEvento(anyString(), any())).thenReturn(201);

        escanearConNmapSiDisponible();

        List<Map<String, Object>> scanEvents = esperarEventoPersistido();
        assertThat(scanEvents).isNotEmpty();

        Map<String, Object> scanEvent = scanEvents.get(0);
        Long attemptId = ((Number) scanEvent.get("id")).longValue();
        assertThat(scanEvent.get("source_ip")).isEqualTo("127.0.0.1");
        assertThat(scanEvent.get("service_attacked")).isEqualTo("honeypot-scan");
        assertThat(scanEvent.get("tipo_ataque")).isEqualTo("escaneo");
        assertThat(scanEvent.get("attempted_command").toString())
                .contains("ftp", "ssh");

        var jsonCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        var idCaptor = org.mockito.ArgumentCaptor.forClass(Long.class);
        verify(siemSenderService, timeout(3000)).enviarEvento(jsonCaptor.capture(), idCaptor.capture());
        assertThat(idCaptor.getValue()).isEqualTo(attemptId);
        assertThat(jsonCaptor.getValue())
                .contains("\"event_id\":\"HP-" + attemptId + "\"")
                .contains("\"event_type\":\"escaneo\"")
                .doesNotContain("\"event_type\":\"nmap\"");

        assertThat(esperarMarcadoComoEnviado(attemptId)).isTrue();
    }

    private boolean esperarMarcadoComoEnviado(Long attemptId) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (System.nanoTime() < deadline) {
            Boolean enviado = jdbcTemplate.queryForObject(
                    "SELECT enviado FROM login_attempts WHERE id = ?", Boolean.class, attemptId);
            if (Boolean.TRUE.equals(enviado)) {
                return true;
            }
            Thread.sleep(25);
        }
        return false;
    }

    private List<Map<String, Object>> esperarEventoPersistido() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        List<Map<String, Object>> scanEvents = List.of();
        while (System.nanoTime() < deadline && scanEvents.isEmpty()) {
            scanEvents = jdbcTemplate.queryForList(
                    "SELECT id, source_ip, service_attacked, tipo_ataque, attempted_command "
                            + "FROM login_attempts "
                            + "WHERE source_ip = ? AND service_attacked = 'honeypot-scan' "
                            + "AND tipo_ataque = 'escaneo'",
                    "127.0.0.1"
            );
            if (scanEvents.isEmpty()) {
                Thread.sleep(25);
            }
        }
        return scanEvents;
    }

    private void escanearConNmapSiDisponible() throws Exception {
        Process nmap;
        try {
            nmap = new ProcessBuilder(
                    "nmap", "-sT", "-Pn", "-n", "--reason", "-p",
                    FTP_PORT + "," + SSH_PORT, "127.0.0.1")
                    .redirectErrorStream(true)
                    .start();
        } catch (IOException e) {
            try (Socket ftp = new Socket("127.0.0.1", FTP_PORT);
                    Socket ssh = new Socket("127.0.0.1", SSH_PORT)) {
                assertThat(ftp.isConnected()).isTrue();
                assertThat(ssh.isConnected()).isTrue();
            }
            return;
        }

        if (!nmap.waitFor(15, TimeUnit.SECONDS)) {
            nmap.destroyForcibly();
            throw new IllegalStateException("Nmap no termino el escaneo TCP local en 15 segundos");
        }

        String output = new String(nmap.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(nmap.exitValue()).withFailMessage(output).isZero();
        assertThat(output).contains(FTP_PORT + "/tcp open", SSH_PORT + "/tcp open");
    }
}
