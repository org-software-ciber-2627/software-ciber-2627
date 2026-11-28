import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SiemMockServer {

    private static final int PORT = 8081;
    private static final String EXPECTED_USER = System.getenv().getOrDefault("IDENTITY_SERVICE_USER", "svc-honeypot");
    private static final String EXPECTED_PASS = System.getenv().getOrDefault("SERVICE_PASSWORD_HONEYPOT", "test-dummy-password");
    private static final String MOCK_JWT = "mock-jwt-g1-honeypot-2026";
    private static final Pattern EVENT_ID_PATTERN = Pattern.compile("\"event_id\"\\s*:\\s*\"([^\"]+)\"");

    private static final AtomicBoolean SIMULAR_503 = new AtomicBoolean(false);

    // 8 campos obligatorios en la raíz acordados con el Grupo 5
    private static final List<String> CAMPOS_OBLIGATORIOS_RAIZ = Arrays.asList(
            "\"event_id\"",
            "\"timestamp\"",
            "\"source\"",
            "\"event_type\"",
            "\"severity\"",
            "\"title\"",
            "\"description\"",
            "\"details\""
    );

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/auth/login", new IdentidadLoginHandler());
        server.createContext("/events", new EventsHandler());
        server.createContext("/admin/503", new Admin503Handler());
        server.setExecutor(null);

        System.out.println("=== Mock Identidad (G1) + SIEM 0.4.0 (G5) arrancado en http://localhost:" + PORT + " ===");
        System.out.println("  - Login Identidad : POST http://localhost:" + PORT + "/auth/login (user=" + EXPECTED_USER + ")");
        System.out.println("  - Ingesta SIEM    : POST http://localhost:" + PORT + "/events");
        System.out.println("  - Simular 503     : POST http://localhost:" + PORT + "/admin/503?activo=true|false\n");
        server.start();
    }

    static class IdentidadLoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                enviarRespuesta(exchange, 405, "{\"error\":\"Metodo no permitido, use POST\"}");
                return;
            }

            if (exchange.getRequestHeaders().containsKey("X-Forwarded-For")) {
                System.out.println("[Identidad Mock] RECHAZADO: Cabecera X-Forwarded-For presente");
                enviarRespuesta(exchange, 400, "{\"error\":\"X-Forwarded-For no permitida\"}");
                return;
            }

            String body = leerBody(exchange);
            boolean credencialesValidas = body.contains("\"username\":\"" + EXPECTED_USER + "\"")
                    && body.contains("\"password\":\"" + EXPECTED_PASS + "\"");

            if (credencialesValidas) {
                System.out.println("[Identidad Mock] Login OK para '" + EXPECTED_USER + "' -> Emitiendo JWT (200)");
                enviarRespuesta(exchange, 200, "{\"token\":\"" + MOCK_JWT + "\"}");
            } else {
                System.out.println("[Identidad Mock] Credenciales invalidas -> 401 Unauthorized");
                enviarRespuesta(exchange, 401, "{\"error\":\"invalid_credentials\"}");
            }
        }
    }

    static class EventsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                enviarRespuesta(exchange, 405, "{\"error\":\"Metodo no permitido, use POST\"}");
                return;
            }

            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            if (!("Bearer " + MOCK_JWT).equals(authHeader)) {
                System.out.println("\n[SIEM Mock] Token ausente o invalido (" + authHeader + ") -> Retornando 401");
                enviarRespuesta(exchange, 401, "{\"error\":\"UNAUTHORIZED\"}");
                return;
            }

            if (SIMULAR_503.get()) {
                System.out.println("\n[SIEM Mock] Modo mantenimiento activo -> Retornando 503 Service Unavailable");
                enviarRespuesta(exchange, 503, "{\"error\":\"STORAGE_UNAVAILABLE\"}");
                return;
            }

            String body = leerBody(exchange);
            System.out.println("\n[SIEM Mock] Evento autenticado recibido:");
            System.out.println(body);

            boolean esValido = true;
            StringBuilder camposFaltantes = new StringBuilder();

            for (String campo : CAMPOS_OBLIGATORIOS_RAIZ) {
                if (!body.contains(campo)) {
                    esValido = false;
                    camposFaltantes.append(campo).append(" ");
                }
            }

            if (esValido && !body.trim().isEmpty()) {
                String eventId = extraerEventId(body);
                System.out.println("-> Validacion OK (event_id=" + eventId + "): Retornando 200 OK");
                String respuesta = "{\"status\":\"accepted\",\"event_id\":\"" + eventId + "\"}";
                enviarRespuesta(exchange, 200, respuesta);
            } else {
                System.out.println("-> Error de validacion. Faltan en raiz: " + camposFaltantes + "-> Retornando 422");
                String respuesta = "{\"status\":\"error\",\"message\":\"Faltan campos obligatorios en la raiz: "
                        + camposFaltantes.toString().replace("\"", "") + "\"}";
                enviarRespuesta(exchange, 422, respuesta);
            }
        }
    }

    static class Admin503Handler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            boolean activar = query != null && query.contains("activo=true");
            SIMULAR_503.set(activar);
            System.out.println("\n[Admin Mock] Simulacion 503 = " + activar);
            enviarRespuesta(exchange, 200, "{\"simular_503\":" + activar + "}");
        }
    }

    private static String extraerEventId(String json) {
        Matcher matcher = EVENT_ID_PATTERN.matcher(json);
        return matcher.find() ? matcher.group(1) : "unknown";
    }

    private static String leerBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void enviarRespuesta(HttpExchange exchange, int statusCode, String responseText) throws IOException {
        byte[] bytes = responseText.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}