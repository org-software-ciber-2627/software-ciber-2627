package com.honeypot.honeypot.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * HP-78: el umbral de fuerza bruta se cambia en la configuración, sin tocar el código.
 * Levanta un contexto de Spring mínimo, solo con FuerzaBrutaConfig.
 */
class FuerzaBrutaConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(FuerzaBrutaConfig.class);

    @Test
    void sinPropiedadesUsaCincoIntentosEnSesentaSegundos() {
        runner.run(contexto -> {
            FuerzaBrutaConfig config = contexto.getBean(FuerzaBrutaConfig.class);
            assertThat(config.getMaxIntentos()).isEqualTo(5);
            assertThat(config.getVentanaSegundos()).isEqualTo(60);
        });
    }

    @Test
    void leeElUmbralDeLaConfiguracion() {
        runner.withPropertyValues(
                        "honeypot.fuerza-bruta.max-intentos=3",
                        "honeypot.fuerza-bruta.ventana-segundos=30")
                .run(contexto -> {
                    FuerzaBrutaConfig config = contexto.getBean(FuerzaBrutaConfig.class);
                    assertThat(config.getMaxIntentos()).isEqualTo(3);
                    assertThat(config.getVentanaSegundos()).isEqualTo(30);
                });
    }
}
