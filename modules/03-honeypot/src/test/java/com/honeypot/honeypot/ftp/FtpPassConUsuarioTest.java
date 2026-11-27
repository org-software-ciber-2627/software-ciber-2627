package com.honeypot.honeypot.ftp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import org.apache.ftpserver.ftplet.FtpReply;
import org.apache.ftpserver.ftplet.FtpRequest;
import org.apache.ftpserver.ftplet.FtpSession;
import org.apache.ftpserver.ftplet.Ftplet;
import org.apache.ftpserver.ftplet.FtpletResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import com.honeypot.honeypot.service.FtpEventService;

class FtpPassConUsuarioTest {

    private FtpEventService ftpEventService;
    private Ftplet ftplet;

    @BeforeEach
    void setUp() {
        ftpEventService = Mockito.mock(FtpEventService.class);
        ftplet = new FtpHoneypot(ftpEventService).createFtplet();
    }

    @Test
    void elPassLlegaConElUserDeLaSesionYResponde530() throws Exception {
        FtpSession sesion = nuevaSesion();

        enviar(sesion, "USER", "admin");
        FtpletResult resultado = enviar(sesion, "PASS", "admin");

        verify(ftpEventService).registrarComando("127.0.0.1", "PASS", "admin", "admin");
        assertEquals(FtpletResult.SKIP, resultado);
        assertEquals(530, ultimaRespuesta(sesion));
    }

    @Test
    void unPassSinUserPrevioLlegaSinUsuarioYResponde530() throws Exception {
        FtpSession sesion = nuevaSesion();

        enviar(sesion, "PASS", "admin");

        verify(ftpEventService).registrarComando(eq("127.0.0.1"), eq("PASS"), eq("admin"), isNull());
        assertEquals(530, ultimaRespuesta(sesion));
    }

    private FtpletResult enviar(FtpSession sesion, String comando, String argumento) throws Exception {
        FtpRequest request = Mockito.mock(FtpRequest.class);
        when(request.getCommand()).thenReturn(comando);
        when(request.getArgument()).thenReturn(argumento);
        return ftplet.beforeCommand(sesion, request);
    }

    private static int ultimaRespuesta(FtpSession sesion) throws Exception {
        ArgumentCaptor<FtpReply> respuestas = ArgumentCaptor.forClass(FtpReply.class);
        verify(sesion, Mockito.atLeastOnce()).write(respuestas.capture());
        return respuestas.getValue().getCode();
    }

    /** Sesión FTP simulada que guarda sus atributos de verdad, como la del servidor. */
    private static FtpSession nuevaSesion() {
        FtpSession sesion = Mockito.mock(FtpSession.class);
        Map<String, Object> atributos = new HashMap<>();

        when(sesion.isLoggedIn()).thenReturn(false);
        when(sesion.getClientAddress()).thenReturn(new InetSocketAddress("127.0.0.1", 12345));
        when(sesion.getAttribute(anyString()))
                .thenAnswer(inv -> atributos.get(inv.<String>getArgument(0)));
        doAnswer(inv -> atributos.put(inv.getArgument(0), inv.getArgument(1)))
                .when(sesion).setAttribute(anyString(), any());
        doAnswer(inv -> atributos.remove(inv.<String>getArgument(0)))
                .when(sesion).removeAttribute(anyString());

        return sesion;
    }
}