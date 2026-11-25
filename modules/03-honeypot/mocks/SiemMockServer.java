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

public class SiemMockServer {

    private static final int PORT = 8081;

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
        server.createContext("/events", new EventsHandler());
        server.setExecutor(null);

        System.out.println("=== SIEM Mock Server arrancado en http://localhost:" + PORT + "/events ===");
        server.start();
    }

    static class EventsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                enviarRespuesta(exchange, 405, "{\"error\": \"Metodo no permitido, use POST\"}");
                return;
            }

            InputStream is = exchange.getRequestBody();
            String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);

            System.out.println("\n[SIEM Mock] Evento recibido:");
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
                System.out.println("-> Validacion OK: Retornando 201 Created");
                String respuesta = "{\"status\": \"created\", \"message\": \"Evento registrado correctamente\"}";
                enviarRespuesta(exchange, 201, respuesta);
            } else {
                System.out.println("-> Error de validacion. Faltan en raiz: " + camposFaltantes + "-> Retornando 422");
                String respuesta = "{\"status\": \"error\", \"message\": \"Faltan campos obligatorios en la raiz: " 
                        + camposFaltantes.toString().replace("\"", "") + "\"}";
                enviarRespuesta(exchange, 422, respuesta);
            }
        }

        private void enviarRespuesta(HttpExchange exchange, int statusCode, String responseText) throws IOException {
            byte[] bytes = responseText.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }
}