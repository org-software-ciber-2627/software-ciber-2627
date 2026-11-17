package com.honeypot.honeypot.service;

import com.honeypot.honeypot.model.EventoPendiente;
import com.honeypot.honeypot.repository.EventoPendienteRepository;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Reenvía al SIEM los eventos pendientes, del más antiguo al más nuevo (HP-22).
 */
@Service
public class ReintentoSiemService {

    private static final Logger log = LoggerFactory.getLogger(ReintentoSiemService.class);

    private final EventoPendienteRepository pendientes;
    private final LoginAttemptRepository loginAttemptRepository;
    private final SiemSenderService siemSenderService;

    public ReintentoSiemService(EventoPendienteRepository pendientes,
                                LoginAttemptRepository loginAttemptRepository,
                                SiemSenderService siemSenderService) {
        this.pendientes = pendientes;
        this.loginAttemptRepository = loginAttemptRepository;
        this.siemSenderService = siemSenderService;
    }

    @Scheduled(initialDelayString = "${honeypot.siem.reintento-ms:30000}",
               fixedDelayString = "${honeypot.siem.reintento-ms:30000}")
    public void reintentar() {
        reintentarPendientes();
    }

    public int reintentarPendientes() {
        int enviados = 0;

        for (EventoPendiente pendiente : pendientes.findTop100ByOrderByIdAsc()) {
            int statusCode = siemSenderService.enviarSinCola(pendiente.getJson());

            if (SiemSenderService.esExito(statusCode)) {
                marcarEnviado(pendiente.getAttemptId());
                pendientes.delete(pendiente);
                enviados++;
            } else if (SiemSenderService.hayQueReintentar(statusCode)) {
                // Se para aquí para no adelantar a este evento con los siguientes
                log.warn("El SIEM sigue sin responder (codigo {}), se reintentara mas tarde", statusCode);
                break;
            } else {
                log.warn("El SIEM rechazo el evento pendiente {} con codigo {}", pendiente.getId(), statusCode);
                pendientes.delete(pendiente);
            }
        }

        if (enviados > 0) {
            log.info("Reenviados {} eventos pendientes al SIEM", enviados);
        }
        return enviados;
    }

    private void marcarEnviado(Long attemptId) {
        if (attemptId == null) {
            return;
        }
        loginAttemptRepository.findById(attemptId).ifPresent(attempt -> {
            attempt.setEnviado(true);
            loginAttemptRepository.save(attempt);
        });
    }
}
