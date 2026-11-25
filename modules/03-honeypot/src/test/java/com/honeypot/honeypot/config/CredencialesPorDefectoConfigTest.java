package com.honeypot.honeypot.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * HP-82: la lista de credenciales por defecto se lee de la configuración.
 */
class CredencialesPorDefectoConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(CredencialesPorDefectoConfig.class);

    @Test
    void leeLaListaDeLaConfiguracion() {
        runner.withPropertyValues("honeypot.credenciales-por-defecto=admin:admin, root:toor")
                .run(contexto -> {
                    CredencialesPorDefectoConfig config = contexto.getBean(CredencialesPorDefectoConfig.class);
                    assertThat(config.getCredenciales()).containsExactlyInAnyOrder("admin:admin", "root:toor");
                    assertThat(config.esPorDefecto("root", "toor")).isTrue();
                    assertThat(config.esPorDefecto("root", "root")).isFalse();
                });
    }

    @Test
    void sinPropiedadLaListaEstaVacia() {
        runner.run(contexto -> {
            CredencialesPorDefectoConfig config = contexto.getBean(CredencialesPorDefectoConfig.class);
            assertThat(config.getCredenciales()).isEmpty();
            assertThat(config.esPorDefecto("admin", "admin")).isFalse();
        });
    }

    @Test
    void conUnCorreoSeComparaLoDeAntesDeLaArroba() {
        CredencialesPorDefectoConfig config = new CredencialesPorDefectoConfig("admin:admin,root:toor");
        assertThat(config.esPorDefecto("admin@admin.com", "admin")).isTrue();
        assertThat(config.esPorDefecto("root@empresa.es", "toor")).isTrue();
        assertThat(config.esPorDefecto("pepe@admin.com", "admin")).isFalse();
        assertThat(config.esPorDefecto("admin@admin.com", "Qwerty.2026")).isFalse();
    }

    @Test
    void sinUsuarioOContrasenaNoEsPorDefecto() {
        CredencialesPorDefectoConfig config = new CredencialesPorDefectoConfig("admin:admin");
        assertThat(config.esPorDefecto(null, "admin")).isFalse();
        assertThat(config.esPorDefecto("admin", null)).isFalse();
    }
}
