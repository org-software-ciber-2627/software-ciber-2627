package com.honeypot.honeypot.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class IpRateLimiterService {

    @Value("${honeypot.rate-limit.max-peticiones}")
    private int maxPeticiones;

    private static final long WINDOW_NANOS = TimeUnit.SECONDS.toNanos(1);

    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    public boolean allowRequest(String ip) {

        long now = System.nanoTime();

        // compute realiza la actualización de forma atómica
        return windows.compute(ip, (key, window) -> {

            // Primera petición o ventana anterior caducada
            if (window == null ||now - window.startNanos >= WINDOW_NANOS) {

                return new Window(now, 1, true);
            }

            // Todavía hay peticiones disponibles
            if (window.count < maxPeticiones) {

                window.count++;

                return window;
            }

            // Se ha superado el límite
            window.allowed = false;

            return window;
        }).allowed;
    }

    private static class Window {

        private final long startNanos;
        private int count;
        private boolean allowed;

        private Window(long startNanos, int count, boolean allowed) {
            this.startNanos = startNanos;
            this.count = count;
            this.allowed = allowed;
        }
    }
}
