package com.honeypot.honeypot.service;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;

/**
 * SIEM para las pruebas: guarda en orden los eventos que acepta y responde 200,
 * salvo que se le indiquen otros códigos con responderCon.
 */
class SiemFalso implements AutoCloseable {

    private final HttpServer servidor;
    private final List<String> recibidos = Collections.synchronizedList(new ArrayList<>());
    private final Deque<Integer> respuestas = new ArrayDeque<>();

    SiemFalso() throws IOException {
        servidor = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        servidor.createContext("/events", exchange -> {
            String cuerpo = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            int codigo;
            synchronized (respuestas) {
                codigo = respuestas.isEmpty() ? 200 : respuestas.poll();
            }
            if (codigo == 200) {
                recibidos.add(cuerpo);
            }
            exchange.sendResponseHeaders(codigo, -1);
            exchange.close();
        });
        servidor.start();
    }

    void responderCon(Integer... codigos) {
        synchronized (respuestas) {
            Collections.addAll(respuestas, codigos);
        }
    }

    String url() {
        return "http://127.0.0.1:" + servidor.getAddress().getPort() + "/events";
    }

    List<String> recibidos() {
        return List.copyOf(recibidos);
    }

    @Override
    public void close() {
        servidor.stop(0);
    }
}
