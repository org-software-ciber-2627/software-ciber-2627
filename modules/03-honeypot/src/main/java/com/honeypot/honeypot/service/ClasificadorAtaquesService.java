package com.honeypot.honeypot.service;

import com.honeypot.honeypot.config.CredencialesPorDefectoConfig;
import com.honeypot.honeypot.config.FuerzaBrutaConfig;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.time.Instant;
import org.springframework.stereotype.Service;

/**
 * Decide qué tipo de ataque es cada intento (HP-12 y HP-25).
 * Está en un servicio para que lo puedan usar el login web, el SSH y el FTP.
 */
@Service
public class ClasificadorAtaquesService {

    public static final String FUERZA_BRUTA = "fuerza_bruta";

    public static final String CREDENCIALES_POR_DEFECTO = "credenciales_por_defecto";

    /** event_type que se envía al SIEM cuando el intento no tiene etiqueta (acuerdo con el grupo 5). */
    public static final String INTENTO_LOGIN = "intento_login";

    private final LoginAttemptRepository loginAttemptRepository;
    private final FuerzaBrutaConfig fuerzaBrutaConfig;
    private final CredencialesPorDefectoConfig credencialesPorDefectoConfig;

    public ClasificadorAtaquesService(LoginAttemptRepository loginAttemptRepository,
            FuerzaBrutaConfig fuerzaBrutaConfig,
            CredencialesPorDefectoConfig credencialesPorDefectoConfig) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.fuerzaBrutaConfig = fuerzaBrutaConfig;
        this.credencialesPorDefectoConfig = credencialesPorDefectoConfig;
    }

    /**
     * Devuelve la etiqueta del intento, o null si no encaja en ningún patrón
     * (en la BD se queda sin etiqueta y al SIEM se envía INTENTO_LOGIN, ver EventoMapper).
     * Se llama ANTES de guardar el intento: si esa IP ya tiene el máximo de intentos
     * dentro de la ventana, el nuevo es el sexto (o más) y se etiqueta como fuerza bruta.
     * Solo cuentan los intentos con contraseña: el FTP guarda una fila por cada comando
     * (USER, LIST...) y esas filas no son intentos de login (HP-78).
     * Si no es fuerza bruta pero el usuario y la contraseña están en la lista de credenciales
     * por defecto, se etiqueta como credenciales_por_defecto. Si es las dos cosas, gana
     * fuerza_bruta (acuerdo con el grupo 5, HP-83).
     */
    public String clasificar(String ip, Instant momento, String usuario, String contrasena) {
        if (esFuerzaBruta(ip, momento)) {
            return FUERZA_BRUTA;
        }
        if (credencialesPorDefectoConfig.esPorDefecto(usuario, contrasena)) {
            return CREDENCIALES_POR_DEFECTO;
        }
        return null;
    }

    private boolean esFuerzaBruta(String ip, Instant momento) {
        if (ip == null || momento == null) {
            return false;
        }
        Instant desde = momento.minusSeconds(fuerzaBrutaConfig.getVentanaSegundos());
        long anteriores = loginAttemptRepository
                .countBySourceIpAndOccurredAtAfterAndCredentialAttemptIsNotNull(ip, desde);
        return anteriores >= fuerzaBrutaConfig.getMaxIntentos();
    }
}