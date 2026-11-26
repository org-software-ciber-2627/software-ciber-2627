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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Autorización por rol y cuenta en HTTP (SEM-142, contrato roles-permissions.md). */
@Import(InMemoryEventTestConfiguration.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=127.0.0.1")
class RoleAuthorizationHttpTests {

    static final String IDS = TestIdentity.bearerAs("svc-ids", "servicio");
    static final String HONEYPOT = TestIdentity.bearerAs("svc-honeypot", "servicio");
    static final String SOAR = TestIdentity.bearerAs("svc-soar", "servicio");
    static final String ANALYST = TestIdentity.bearerAs("ana", "analista");
    static final String ADMIN = TestIdentity.bearerAs("root", "admin");
    static final String UNKNOWN_ROLE = TestIdentity.bearerAs("otro", "desconocido");

    @Autowired
    Environment environment;
    @Autowired
    ObjectMapper mapper;
    @Autowired
    EventRepository events;

    final HttpClient client = HttpClient.newHttpClient();
    String baseUrl;

    @BeforeEach
    void setUp() {
        baseUrl = "http://127.0.0.1:" + environment.getProperty("local.server.port");
    }

    HttpResponse<String> get(String path, String authorization) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", authorization).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> postEvent(String body, String authorization) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(baseUrl + "/events"))
                .header("Content-Type", "application/json")
                .header("Authorization", authorization)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    /** Ejemplo del contrato con un event_id propio, para no chocar con otros tests del mismo contexto. */
    ObjectNode example(String file) throws Exception {
        var json = (ObjectNode) mapper.readTree(Files.readString(Path.of("contract/examples", file)));
        json.put("event_id", "sem142-" + System.nanoTime());
        return json;
    }

    void assertError(HttpResponse<String> response, String code) throws Exception {
        assertEquals(403, response.statusCode(), response.body());
        assertEquals(code, mapper.readTree(response.body()).get("error").get("code").asText());
    }

    @Test
    void producerPublishesItsOwnSource() throws Exception {
        var event = example("grupo_2_ids_ejemplo_propuesto.json");
        var response = postEvent(mapper.writeValueAsString(event), IDS);
        assertEquals(200, response.statusCode(), response.body());
        assertFalse(events.findById("ids", event.get("event_id").asText()).isEmpty());
    }

    @Test
    void producerPublishingAnotherSourceIsRejectedWithoutStoring() throws Exception {
        var event = example("grupo_3_honeypot.json");
        assertError(postEvent(mapper.writeValueAsString(event), IDS), "SOURCE_MISMATCH");
        assertTrue(events.findById("honeypot", event.get("event_id").asText()).isEmpty());
        // La cuenta correcta sí puede publicar el mismo evento.
        assertEquals(200, postEvent(mapper.writeValueAsString(event), HONEYPOT).statusCode());
    }

    @Test
    void nonProducersCannotPublishEvents() throws Exception {
        var event = example("grupo_2_ids_ejemplo_propuesto.json");
        String body = mapper.writeValueAsString(event);
        for (String account : new String[] {SOAR, ANALYST, ADMIN, UNKNOWN_ROLE}) {
            assertError(postEvent(body, account), "FORBIDDEN");
        }
        assertTrue(events.findById("ids", event.get("event_id").asText()).isEmpty());
    }

    @Test
    void eventHistoryIsOnlyForHumans() throws Exception {
        // Este contexto usa un almacén en memoria sin histórico (findPage no está implementado),
        // así que aquí solo se comprueba que la matriz deja pasar a analista y admin.
        // El contenido del histórico ya lo prueban EventHistoryHttpTests.
        for (String account : new String[] {ANALYST, ADMIN}) {
            int status = get("/events", account).statusCode();
            assertTrue(status != 401 && status != 403, account + " recibió " + status);
        }
        assertError(get("/events", SOAR), "FORBIDDEN");
        assertError(get("/events", IDS), "FORBIDDEN");
    }

    @Test
    void alertsAreForSoarAndHumans() throws Exception {
        for (String account : new String[] {SOAR, ANALYST, ADMIN}) {
            assertEquals(200, get("/alerts", account).statusCode(), account);
            assertEquals(404, get("/alerts/NO-EXISTE", account).statusCode(), account);
        }
        assertError(get("/alerts", HONEYPOT), "FORBIDDEN");
        assertError(get("/alerts/NO-EXISTE", HONEYPOT), "FORBIDDEN");
    }

    @Test
    void unknownRoleAndPathTricksAreDenied() throws Exception {
        assertError(get("/alerts", UNKNOWN_ROLE), "FORBIDDEN");
        // No se puede llegar al histórico disfrazando la ruta como si fuera una alerta.
        assertError(get("/alerts/x/../../events", SOAR), "FORBIDDEN");
    }

    @Test
    void healthStaysPublic() throws Exception {
        var request = HttpRequest.newBuilder(URI.create(baseUrl + "/health")).GET().build();
        assertEquals(200, client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
    }
}