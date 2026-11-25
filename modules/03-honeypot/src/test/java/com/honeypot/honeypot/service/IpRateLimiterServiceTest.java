package com.honeypot.honeypot.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class IpRateLimiterServiceTest {

    private IpRateLimiterService limitador(int max) {
        IpRateLimiterService limitador = new IpRateLimiterService();
        ReflectionTestUtils.setField(limitador, "maxPeticiones", max);
        return limitador;
    }

    // HP-32: pasan 10 (más que el umbral de fuerza bruta) y la 11 se rechaza
    @Test
    void laPeticionOnceEnElMismoSegundoSeRechaza() {
        IpRateLimiterService limitador = limitador(10);
        for (int i = 0; i < 10; i++) {
            assertTrue(limitador.allowRequest("203.0.113.50"));
        }
        assertFalse(limitador.allowRequest("203.0.113.50"));
    }

    @Test
    void cadaIpTieneSuPropioLimite() {
        IpRateLimiterService limitador = limitador(10);
        for (int i = 0; i < 11; i++) {
            limitador.allowRequest("203.0.113.51");
        }
        assertTrue(limitador.allowRequest("203.0.113.52"));
    }
}
