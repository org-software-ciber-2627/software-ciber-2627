package com.honeypot.honeypot.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.honeypot.honeypot.repository.LoginAttemptRepository;
import com.honeypot.honeypot.service.ClasificadorAtaquesService;
import com.honeypot.honeypot.service.DetectorEscaneoService;
import com.honeypot.honeypot.service.EventoMapper;
import com.honeypot.honeypot.service.IpRateLimiterService;
import com.honeypot.honeypot.service.RechazoResumenService;
import com.honeypot.honeypot.service.SiemSenderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

// HP-103: el login web envía al SIEM la severidad que marca EventoMapper.severidadDe
class HoneyPotControllerSiemTest {

    private static final String IP = "203.0.113.80";

    private ClasificadorAtaquesService clasificador;
    private SiemSenderService siem;
    private HoneyPotController controller;

    @BeforeEach
    void preparar() {
        clasificador = mock(ClasificadorAtaquesService.class);
        siem = mock(SiemSenderService.class);

        IpRateLimiterService limitador = mock(IpRateLimiterService.class);
        when(limitador.allowRequest(anyString())).thenReturn(true);

        controller = new HoneyPotController(
                mock(LoginAttemptRepository.class),
                new EventoMapper(),
                siem,
                limitador,
                clasificador,
                mock(DetectorEscaneoService.class),
                mock(RechazoResumenService.class));
    }

    @Test
    void unLoginConCredencialPorDefectoLlegaAlSiemConSeveridadHigh() {
        when(clasificador.clasificar(eq(IP), any(), eq("root"), eq("toor")))
                .thenReturn(ClasificadorAtaquesService.CREDENCIALES_POR_DEFECTO);

        enviarLogin("root", "toor");

        assertThat(jsonEnviado())
                .contains("\"event_type\":\"credenciales_por_defecto\"")
                .contains("\"severity\":\"high\"");
    }

    @Test
    void unLoginSinClasificarLlegaAlSiemComoIntentoLoginConSeveridadLow() {
        // El clasificador (mock) devuelve null: el intento no tiene etiqueta
        enviarLogin("pepe@example.test", "clave");

        assertThat(jsonEnviado())
                .contains("\"event_type\":\"intento_login\"")
                .contains("\"severity\":\"low\"");
    }

    private void enviarLogin(String usuario, String password) {
        MultiValueMap<String, String> parametros = new LinkedMultiValueMap<>();
        parametros.add("email", usuario);
        parametros.add("password", password);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setRemoteAddr(IP);

        controller.submitLogin(parametros, request, new MockHttpServletResponse(), new ExtendedModelMap());
    }

    private String jsonEnviado() {
        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        // El envío es en segundo plano: timeout espera hasta 2 s a que ocurra
        verify(siem, timeout(2000)).enviarEvento(json.capture(), any());
        return json.getValue();
    }
}
