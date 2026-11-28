package com.honeypot.honeypot.ftp;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:honeypot-test;DB_CLOSE_DELAY=-1")
@ActiveProfiles("dev")
class FtpHoneypotIntegrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void comandosSinLoginSeRechazanYSeGuardanEnBaseDeDatos() throws Exception {
        List<String> commands = List.of(
                "LIST prueba",
                "CWD /prueba",
                "RETR prueba.txt"
        );

        try (Socket socket = new Socket("127.0.0.1", 2121);
                BufferedReader input = new BufferedReader(
                        new InputStreamReader(
                                socket.getInputStream(),
                                StandardCharsets.UTF_8));
                BufferedWriter output = new BufferedWriter(
                        new OutputStreamWriter(
                                socket.getOutputStream(),
                                StandardCharsets.UTF_8))) {
            socket.setSoTimeout(3000);
            assertThat(input.readLine()).startsWith("220");

            for (String command : commands) {
                output.write(command);
                output.write("\r\n");
                output.flush();

                assertThat(input.readLine())
                        .isEqualTo("530 Not logged in.");
            }
        }

        List<Map<String, Object>> savedCommands = jdbcTemplate.queryForList(
                "SELECT source_ip, occurred_at, attempted_command "
                        + "FROM login_attempts "
                        + "WHERE service_attacked = 'ftp' "
                        + "AND attempted_command IN (?, ?, ?)",
                "LIST prueba",
                "CWD /prueba",
                "RETR prueba.txt"
        );

        assertThat(savedCommands).hasSize(3);
        assertThat(savedCommands)
                .extracting(row -> row.get("attempted_command"))
                .containsExactlyInAnyOrderElementsOf(commands);
        assertThat(savedCommands)
                .allSatisfy(row -> {
                    assertThat(row.get("source_ip")).isEqualTo("127.0.0.1");
                    assertThat(row.get("occurred_at")).isNotNull();
                });
    }
}
