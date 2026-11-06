package com.honeypot.honeypot.ssh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.honeypot.honeypot.model.LoginAttempt;
import com.honeypot.honeypot.repository.LoginAttemptRepository;
import com.honeypot.honeypot.service.ClasificadorAtaquesService;
import com.honeypot.honeypot.service.EventoMapper;
import com.honeypot.honeypot.service.SiemSenderService;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class SshAttemptRecorderTest {

    private final Instant ahora = Instant.parse("2026-11-03T12:00:00Z");

    private LoginAttemptRepository repositorio;
    private ClasificadorAtaquesService clasificador;
    private SshAttemptRecorder recorder;

    @BeforeEach
    void preparar() {
        repositorio = mock(LoginAttemptRepository.class);
        clasificador = mock(ClasificadorAtaquesService.class);
        recorder = new SshAttemptRecorder(repositorio, clasificador, new EventoMapper(), mock(SiemSenderService.class));
    }

    // HP-67: un intento con contraseña se guarda con servicio, usuario, contraseña y la etiqueta del clasificador
    @Test
    void unIntentoConContrasenaSeGuardaClasificado() {
        when(clasificador.clasificar(eq("203.0.113.70"), eq(ahora), eq("root"), eq("toor")))
                .thenReturn(ClasificadorAtaquesService.CREDENCIALES_POR_DEFECTO);

        recorder.onAttempt(new SshAttemptData("203.0.113.70", 50000, ahora, "root",
                SshAttemptData.AuthMethod.PASSWORD, "toor", null, "SSH-2.0-OpenSSH_9.6"));

        LoginAttempt guardado = guardado();
        assertEquals("honeypot-ssh", guardado.getServiceAttacked());
        assertEquals("root", guardado.getUsername());
        assertEquals("toor", guardado.getCredentialAttempt());
        assertEquals(ClasificadorAtaquesService.CREDENCIALES_POR_DEFECTO, guardado.getTipoAtaque());
    }

    // La huella de la clave pública se registra, pero no como contraseña: no cuenta para la fuerza bruta
    @Test
    void unIntentoConClavePublicaNoGuardaContrasena() {
        recorder.onAttempt(new SshAttemptData("203.0.113.71", 50001, ahora, "root",
                SshAttemptData.AuthMethod.PUBLIC_KEY, null, "SHA256:abc123", "SSH-2.0-OpenSSH_9.6"));

        LoginAttempt guardado = guardado();
        assertNull(guardado.getCredentialAttempt());
        assertEquals("publickey SHA256:abc123", guardado.getAttemptedCommand());
    }

    private LoginAttempt guardado() {
        ArgumentCaptor<LoginAttempt> captor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(repositorio, atLeastOnce()).save(captor.capture());
        return captor.getAllValues().get(0);
    }
}
