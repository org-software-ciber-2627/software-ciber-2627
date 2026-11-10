package com.honeypot.honeypot.service;

import com.honeypot.honeypot.model.RechazoResumen;
import com.honeypot.honeypot.repository.RechazoResumenRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.stereotype.Service;

/**
 * Guarda un resumen de las peticiones que rechaza el limitador (HP-88).
 * En vez de una fila por petición rechazada (que llenaría la BD durante un ataque),
 * hay una sola fila por IP, minuto y servicio, y se va sumando el número de rechazos.
 * Al terminar el minuto, esa fila queda con el total. En este sprint no se envía al SIEM (HP-86).
 */
@Service
public class RechazoResumenService {

    private final RechazoResumenRepository repositorio;

    public RechazoResumenService(RechazoResumenRepository repositorio) {
        this.repositorio = repositorio;
    }

    // synchronized: con muchas peticiones a la vez, dos hilos podrían crear la misma fila dos veces
    public synchronized void registrarRechazo(String ip, String servicio, Instant momento) {
        Instant minuto = momento.truncatedTo(ChronoUnit.MINUTES);
        RechazoResumen resumen = repositorio.findByIpAndMinutoAndServicio(ip, minuto, servicio)
                .orElseGet(() -> new RechazoResumen(ip, minuto, servicio));
        resumen.sumarRechazo();
        repositorio.save(resumen);
    }
}
