package com.honeypot.honeypot.controller;

import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import com.honeypot.honeypot.service.ClasificadorAtaquesService;
import com.honeypot.honeypot.service.EventoMapper;
import com.honeypot.honeypot.service.IpRateLimiterService;
import com.honeypot.honeypot.service.SiemSenderService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class HoneyPotController {
    private static final Logger log = LoggerFactory.getLogger(HoneyPotController.class);

    private final LoginAttemptRepository loginAttemptRepository;
    private final EventoMapper eventoMapper;
    private final SiemSenderService siemSenderService;
    private final JsonMapper jsonMapper = JsonMapper.builder().build();
    private final IpRateLimiterService ipRateLimiterService;
    private final ClasificadorAtaquesService clasificadorAtaquesService;

    public HoneyPotController(
            LoginAttemptRepository loginAttemptRepository,
            EventoMapper eventoMapper,
            SiemSenderService siemSenderService,
            IpRateLimiterService ipRateLimiterService,
            ClasificadorAtaquesService clasificadorAtaquesService
    ) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.eventoMapper = eventoMapper;
        this.siemSenderService = siemSenderService;
        this.ipRateLimiterService = ipRateLimiterService;
        this.clasificadorAtaquesService = clasificadorAtaquesService;
    }

    @GetMapping({"/", "/login"})
    public String login() {
        return "login";
    }

    @PostMapping("/login")
    public String submitLogin(@RequestParam MultiValueMap<String, String> parameters,
            HttpServletRequest request, HttpServletResponse response,  Model model) {
        String password = firstValue(parameters, "password", "pass", "pwd");

        String ip = request.getRemoteAddr();
        //Cpmprueba el limite antes de procesar el intento
        boolean allowed = ipRateLimiterService.allowRequest(ip);

        if (!allowed) {
            response.setStatus(429);
            model.addAttribute("message", "Demasiadas peticiones. Inténtalo de nuevo más tarde.");
            // No guardar en BD, no clasificar y no enviar al SIEM.
            // No registrar cada rechazo para evitar inundar los logs.
            return "login";
        }

        LoginAttempt attempt = new LoginAttempt();
        attempt.setSourceIp(request.getRemoteAddr());
        attempt.setOccurredAt(Instant.now());
        attempt.setServiceAttacked("honeypot-web");
        attempt.setUsername(truncate(firstValue(parameters, "email", "username", "user"), 320));
        attempt.setCredentialAttempt(truncate(password, 2000));
        attempt.setPasswordLength(password == null ? null : password.length());
        attempt.setAttemptedCommand(truncate(firstValue(parameters, "command", "cmd"), 2000));
        attempt.setRequestPath(truncate(request.getRequestURI(), 512));
        attempt.setUserAgent(truncate(request.getHeader("User-Agent"), 512));

        // Clasificar el intento antes de guardarlo (HP-76 y HP-83)
        attempt.setTipoAtaque(clasificadorAtaquesService.clasificar(
                attempt.getSourceIp(), attempt.getOccurredAt(),
                attempt.getUsername(), attempt.getCredentialAttempt()));

        // 1. Guardar primero para que la BD asigne el ID
        loginAttemptRepository.save(attempt);

        // 2. Enviar en segundo plano para no demorar la respuesta al atacante
        CompletableFuture.runAsync(() -> {
            try {
                // event_type: la etiqueta guardada o "intento_login" si no tiene (HP-77)
                // Severidad "high" para credenciales por defecto, como en contract/examples
                String severidad = ClasificadorAtaquesService.CREDENCIALES_POR_DEFECTO
                        .equals(attempt.getTipoAtaque()) ? "high" : "medium";
                EventoContrato evento = eventoMapper.mapearAEvento(attempt, severidad);
                String json = jsonMapper.writeValueAsString(evento);

                int statusCode = siemSenderService.enviarEvento(json);

                if (statusCode == 200 || statusCode == 201) {
                    attempt.setEnviado(true);
                    loginAttemptRepository.save(attempt);
                    log.info("Evento {} enviado al SIEM con exito (HTTP {})", evento.eventId(), statusCode);
                } else {
                    log.warn("El SIEM respondio con codigo no exitoso: {} para el evento {}", statusCode, evento.eventId());
                }
            } catch (Exception e) {
                log.warn("Error al procesar o enviar evento al SIEM: {}", e.getMessage());
            }
        });

        // La contraseña no se escribe en el log a propósito.
        log.info("Intento guardado: ip={} servicio={} usuario={} total={}",
                attempt.getSourceIp(), attempt.getServiceAttacked(),
                limpiar(attempt.getUsername()), loginAttemptRepository.count());

        model.addAttribute("message", "Credenciales incorrectas.");

        return "login";
    }

    private static String firstValue(MultiValueMap<String, String> parameters, String... names) {
        for (String name : names) {
            List<String> values = parameters.get(name);
            if (values != null && !values.isEmpty()) {
                return values.get(0);
            }
        }
        return null;
    }

    private static String truncate(String value, int maxLength) {
        return value == null || value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    // El usuario lo escribe el atacante: quitamos los saltos de línea
    // para que no pueda inventarse líneas falsas en nuestros logs (log injection).
    private static String limpiar(String value) {
        return value == null ? null : value.replaceAll("[\\r\\n]", "_");
    }
}