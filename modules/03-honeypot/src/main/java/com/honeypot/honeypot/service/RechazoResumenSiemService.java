package com.honeypot.honeypot.service;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;
import com.honeypot.honeypot.model.EventoContrato;
import com.honeypot.honeypot.model.RechazoResumen;
import com.honeypot.honeypot.repository.RechazoResumenRepository;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Envía al SIEM el resumen de peticiones rechazadas al acabar cada minuto (HP-104).
 */
@Service
public class RechazoResumenSiemService {

    private static final Logger log = LoggerFactory.getLogger(RechazoResumenSiemService.class);

    // PROVISIONALES: cambiarlos cuando se acuerde el event_type y la severidad con el grupo 5
    static final String EVENT_TYPE = "peticiones_rechazadas";
    static final String SEVERITY = "info";

    private final RechazoResumenRepository repositorio;
    private final SiemSenderService siemSenderService;
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    public RechazoResumenSiemService(RechazoResumenRepository repositorio,
                                     SiemSenderService siemSenderService) {
        this.repositorio = repositorio;
        this.siemSenderService = siemSenderService;
    }

    // En el segundo 5 de cada minuto, para no coincidir con el cambio de minuto
    @Scheduled(cron = "5 * * * * *")
    public void enviarResumenes() {
        enviarResumenesAnterioresA(Instant.now());
    }

    // Recibe la hora como parámetro para poder probarlo sin esperar al minuto
    public int enviarResumenesAnterioresA(Instant ahora) {
        Instant minutoActual = ahora.truncatedTo(ChronoUnit.MINUTES);
        int tratados = 0;

        for (RechazoResumen fila : repositorio.findByEnviadoFalseAndMinutoBefore(minutoActual)) {
            try {
                String json = jsonMapper.writeValueAsString(aEvento(fila));
                int status = siemSenderService.enviarEvento(json, null);
                if (status >= 400 && status < 500) {
                    log.warn("El SIEM rechazo el resumen {} con codigo {}", fila.getId(), status);
                }
                fila.setEnviado(true);
                repositorio.save(fila);
                tratados++;
            } catch (JacksonException e) {
                log.error("No se pudo convertir a JSON el resumen {}", fila.getId(), e);
            }
        }
        return tratados;
    }

    EventoContrato aEvento(RechazoResumen fila) {
        String minuto = DateTimeFormatter.ISO_INSTANT.format(fila.getMinuto().truncatedTo(ChronoUnit.SECONDS));

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("source_ip", fila.getIp());
        details.put("service", fila.getServicio());
        details.put("minuto", minuto);
        details.put("rechazos", fila.getRechazos());

        return new EventoContrato(
                "HP-R-" + fila.getId(),
                minuto,
                "honeypot",
                EVENT_TYPE,
                SEVERITY,
                "Peticiones rechazadas por el limitador",
                fila.getRechazos() + " peticiones rechazadas desde " + fila.getIp()
                        + " en " + fila.getServicio() + " durante el minuto " + minuto,
                details
        );
    }
}