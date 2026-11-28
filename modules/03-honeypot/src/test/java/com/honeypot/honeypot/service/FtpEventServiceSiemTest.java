package com.honeypot.honeypot.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

//el PASS del FTP con credencial por defecto llega al SIEM con su etiqueta.
class FtpEventServiceSiemTest {

    private ClasificadorAtaquesService clasificador;
    private SiemSenderService siem;
    private FtpEventService ftpEventService;

    @BeforeEach
    void setUp() {
        LoginAttemptRepository repositorio = Mockito.mock(LoginAttemptRepository.class);
        when(repositorio.save(any(LoginAttempt.class))).thenAnswer(inv -> inv.getArgument(0));

        clasificador = Mockito.mock(ClasificadorAtaquesService.class);
        siem = Mockito.mock(SiemSenderService.class);
        when(siem.enviarEvento(anyString(), any())).thenReturn(200);

        ftpEventService = new FtpEventService(
                repositorio, new EventoMapper(), siem, clasificador, Mockito.mock(DetectorEscaneoService.class));
    }

    @Test
    void elPassSeClasificaConElUserDeLaSesionYLlegaAlSiemConSuEtiqueta() {
        when(clasificador.clasificar(eq("203.0.113.9"), any(), eq("admin"), eq("admin")))
                .thenReturn(ClasificadorAtaquesService.CREDENCIALES_POR_DEFECTO);

        ftpEventService.registrarComando("203.0.113.9", "PASS", "admin", "admin");

        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        verify(siem, timeout(2000)).enviarEvento(json.capture(), any());
        assertThat(json.getValue())
                .contains("\"event_type\":\"credenciales_por_defecto\"")
                .contains("\"username\":\"admin\"");
    }

    // HP-103: la severidad sale de EventoMapper.severidadDe según el event_type
    @Test
    void elPassConCredencialPorDefectoLlegaAlSiemConSeveridadHigh() {
        when(clasificador.clasificar(eq("203.0.113.9"), any(), eq("admin"), eq("admin")))
                .thenReturn(ClasificadorAtaquesService.CREDENCIALES_POR_DEFECTO);

        ftpEventService.registrarComando("203.0.113.9", "PASS", "admin", "admin");

        assertThat(jsonEnviado()).contains("\"severity\":\"high\"");
    }

    @Test
    void elPassSinClasificarLlegaAlSiemComoIntentoLoginConSeveridadLow() {
        // El clasificador (mock) devuelve null: el PASS no tiene etiqueta
        ftpEventService.registrarComando("203.0.113.9", "PASS", "secreta", "admin");

        assertThat(jsonEnviado())
                .contains("\"event_type\":\"intento_login\"")
                .contains("\"severity\":\"low\"");
    }

    private String jsonEnviado() {
        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        verify(siem, timeout(2000)).enviarEvento(json.capture(), any());
        return json.getValue();
    }
}