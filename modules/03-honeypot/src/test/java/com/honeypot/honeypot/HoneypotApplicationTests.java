package com.honeypot.honeypot;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.beans.factory.annotation.Autowired;

@SpringBootTest(
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = "spring.datasource.url=jdbc:h2:mem:honeypot-test;DB_CLOSE_DELAY=-1")
@ActiveProfiles("dev")
class HoneypotApplicationTests {
	@Value("${local.server.port}")
	private int port;

	@Autowired
	private JdbcTemplate jdbcTemplate;


	@Test
	void contextLoads() {
	}

	@Test
	void attemptsPageRenders() throws Exception {
		String form = "email=" + encode("attempts@example.test")
				+ "&password=" + encode("probe-password")
				+ "&command=" + encode("whoami");
		HttpRequest loginRequest = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/login"))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString(form))
				.build();
		HttpClient client = HttpClient.newHttpClient();
		client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

		HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/attempts"))
				.GET()
				.build();

		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

		assertThat(response.statusCode()).isEqualTo(200);
		assertThat(response.body()).contains("Intentos registrados");
		assertThat(response.body()).contains("IP de origen", "Timestamp (UTC, ISO 8601)", "Servicio atacado",
				"Usuario", "Credencial intentada", "attempts@example.test", "probe-password", "honeypot-web");
		assertThat(response.body()).containsPattern("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z");
	}

	@Test
	void clearAttemptsRemovesAllLogs() throws Exception {
		String form = "email=" + encode("clear@example.test") + "&password=" + encode("probe-password");
		HttpRequest loginRequest = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/login"))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString(form))
				.build();
		HttpClient client = HttpClient.newHttpClient();
		client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

		HttpRequest clearRequest = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/attempts/clear"))
				.POST(HttpRequest.BodyPublishers.noBody())
				.build();
		HttpResponse<String> clearResponse = client.send(clearRequest, HttpResponse.BodyHandlers.ofString());

		assertThat(clearResponse.statusCode()).isEqualTo(302);
		assertThat(clearResponse.headers().firstValue("Location"))
				.hasValue("http://localhost:" + port + "/attempts");
		assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM login_attempts", Integer.class)).isZero();

		HttpRequest attemptsRequest = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/attempts"))
				.GET()
				.build();
		HttpResponse<String> attemptsResponse = client.send(attemptsRequest, HttpResponse.BodyHandlers.ofString());
		assertThat(attemptsResponse.body()).contains("Todavía no hay intentos registrados.");
	}

	@Test
	void loginAttemptIsPersistedWithNormalizedFields() throws Exception {
		String form = "email=" + encode("probe@example.test")
				+ "&password=" + encode("not-stored-secret")
				+ "&command=" + encode("whoami");
		HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/login"))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString(form))
				.build();

		HttpResponse<String> response = HttpClient.newHttpClient()
				.send(request, HttpResponse.BodyHandlers.ofString());

		assertThat(response.statusCode()).isEqualTo(200);
		assertThat(response.body()).contains("Credenciales incorrectas.");

		Map<String, Object> attempt = jdbcTemplate.queryForMap(
				"SELECT source_ip, occurred_at, service_attacked, username, credential_attempt, password_length, attempted_command "
						+ "FROM login_attempts WHERE username = ?",
					"probe@example.test");
		assertThat(attempt.get("source_ip")).isNotNull();
		assertThat(attempt.get("occurred_at")).isNotNull();
		assertThat(attempt.get("service_attacked")).isEqualTo("honeypot-web");
		assertThat(attempt.get("credential_attempt")).isEqualTo("not-stored-secret");
		assertThat(attempt.get("password_length")).isEqualTo(17);
		assertThat(attempt.get("attempted_command")).isEqualTo("whoami");
	}

	private static String encode(String value) {
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

}