package com.honeypot.honeypot.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Umbral para detectar ataques de fuerza bruta (HP-12).
 * Los valores se leen de application.properties. Si faltan, se usan 5 intentos en 60 segundos.
 */
@Component
public class FuerzaBrutaConfig {

    @Value("${honeypot.fuerza-bruta.max-intentos:5}")
    private int maxIntentos;

    @Value("${honeypot.fuerza-bruta.ventana-segundos:60}")
    private int ventanaSegundos;

    public int getMaxIntentos() {
        return maxIntentos;
    }

    public int getVentanaSegundos() {
        return ventanaSegundos;
    }
}