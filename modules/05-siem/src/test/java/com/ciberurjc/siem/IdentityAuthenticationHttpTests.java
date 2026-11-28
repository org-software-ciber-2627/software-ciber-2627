package com.ciberurjc.siem;

import com.ciberurjc.siem.repositories.EventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Comportamiento HTTP de la autenticación con Identidad (SEM-133, contrato identity-auth.md). */
@Import(InMemoryEventTestConfiguration.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=127.0.0.1")
class IdentityAuthenticationHttpTests {

    @Autowired
    Environment environment;
    @Autowired
    ObjectMapper mapper;
    @Autowired
    TestIdentityValidator identity;
    @Autowired
    EventRepository events;

    /** Cliente sin token automático: aquí cada test decide qué cabecera envía. */
    final HttpClient client = HttpClient.newHttpClient();
    String baseUrl;

    @BeforeEach
    void setUp() {
        baseUrl = "http://127.0.0.1:" + environment.getProperty("local.server.port");
        identity.reset();
    }

    HttpResponse<String> get(String path, String authorization) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
        if (authorization != null) {
            builder.header("Authorization", authorization);
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> postEvent(String body, String authorization) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(baseUrl + "/events"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (authorization != null) {
            builder.header("Authorization", authorization);
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    void assertUnauthenticated(HttpResponse<String> response) throws Exception {
        assertEquals(401, response.statusCode(), response.body());
        assertEquals("Bearer", response.headers().firstValue("WWW-Authenticate").orElse(null));
        assertEquals("UNAUTHENTICATED", mapper.readTree(response.body()).get("error").get("code").asText());
    }

    @Test
    void healthIsPublicAndDoesNotCallIdentity() throws Exception {
        assertEquals(200, get("/health", null).statusCode());
        assertEquals(0, identity.calls());
    }

    @Test
    void protectedOperationsWithoutTokenAreRejectedWithoutCallingIdentity() throws Exception {
        for (String path : List.of("/events", "/alerts", "/alerts/ANY-ID", "/unknown-route")) {
            assertUnauthenticated(get(path, null));
        }
        assertUnauthenticated(postEvent("{}", null));
        assertEquals(0, identity.calls());
    }

    @Test
    void malformedAuthorizationIsRejectedWithoutCallingIdentity() throws Exception {
        for (String header : List.of("Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Bearer a b", TestIdentity.VALID_TOKEN)) {
            assertUnauthenticated(get("/alerts", header));
        }
        assertEquals(0, identity.calls());
    }

    @Test
    void tokenRejectedByIdentityReturns401() throws Exception {
        assertUnauthenticated(get("/alerts", "Bearer token-rechazado"));
        assertEquals(1, identity.calls());
    }

    @Test
    void validTokenReachesTheOperation() throws Exception {
        var response = get("/alerts", TestIdentity.BEARER);
        assertEquals(200, response.statusCode(), response.body());
        assertEquals(200, get("/alerts", "bearer " + TestIdentity.VALID_TOKEN).statusCode());
    }

    @Test
    void identityUnavailableDeniesAccessWith503() throws Exception {
        var response = get("/alerts", "Bearer " + TestIdentity.UNAVAILABLE_TOKEN);
        assertEquals(503, response.statusCode(), response.body());
        assertEquals("30", response.headers().firstValue("Retry-After").orElse(null));
        assertEquals("IDENTITY_UNAVAILABLE", mapper.readTree(response.body()).get("error").get("code").asText());
    }

    @Test
    void rejectedIngestionStoresNothing() throws Exception {
        // Identificador propio para no depender de lo que hayan guardado otros tests en el mismo contexto.
        var json = (ObjectNode) mapper.readTree(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json")));
        String eventId = "sem133-auth-check-" + System.nanoTime();
        json.put("event_id", eventId);
        String source = json.get("source").asText();
        String event = mapper.writeValueAsString(json);

        assertUnauthenticated(postEvent(event, null));
        assertUnauthenticated(postEvent(event, "Bearer token-rechazado"));
        assertEquals(503, postEvent(event, "Bearer " + TestIdentity.UNAVAILABLE_TOKEN).statusCode());
        assertTrue(events.findById(source, eventId).isEmpty());

        assertEquals(200, postEvent(event, TestIdentity.BEARER).statusCode());
        assertFalse(events.findById(source, eventId).isEmpty());
    }
}
