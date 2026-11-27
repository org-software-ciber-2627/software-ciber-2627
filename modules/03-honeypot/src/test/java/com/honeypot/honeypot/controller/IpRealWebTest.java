package com.honeypot.honeypot.controller;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:h2:mem:honeypot-ip-real-test;DB_CLOSE_DELAY=-1",
                "server.forward-headers-strategy=native",
                "honeypot.ftp.port=2124",
                "honeypot.ssh.port=2225"
        })
@ActiveProfiles("dev")
class IpRealWebTest {

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // HP-122: detrás del proxy el intento se guarda con la IP que manda en X-Forwarded-For
    @Test
    void usaLaIpDeXForwardedFor() throws Exception {
        enviarLogin("xff@example.test", "203.0.113.20");

        assertThat(ipGuardada("xff@example.test")).isEqualTo("203.0.113.20");
    }

    // HP-122: sin la cabecera se sigue usando la IP de la conexión
    @Test
    void sinCabeceraUsaLaIpDeLaConexion() throws Exception {
        enviarLogin("directo@example.test", null);

        assertThat(ipGuardada("directo@example.test")).isEqualTo("127.0.0.1");
    }

    private void enviarLogin(String email, String xForwardedFor) throws Exception {
        HttpRequest.Builder peticion = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("email=" + URLEncoder.encode(email, StandardCharsets.UTF_8) + "&password=prueba"));
        if (xForwardedFor != null) {
            peticion.header("X-Forwarded-For", xForwardedFor);
        }
        HttpClient.newHttpClient().send(peticion.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String ipGuardada(String email) {
        return jdbcTemplate.queryForObject(
                "SELECT source_ip FROM login_attempts WHERE username = ?", String.class, email);
    }
}
