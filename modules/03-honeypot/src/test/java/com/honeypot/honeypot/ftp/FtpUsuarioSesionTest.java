package com.honeypot.honeypot.ftp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import org.apache.ftpserver.ftplet.FtpRequest;
import org.apache.ftpserver.ftplet.FtpSession;
import org.apache.ftpserver.ftplet.Ftplet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.honeypot.honeypot.service.FtpEventService;

/**
 * HP-93: el FTP recuerda el USER de cada sesión para juntarlo después con el PASS.
 */
class FtpUsuarioSesionTest {

    private Ftplet ftplet;

    @BeforeEach
    void setUp() {
        FtpEventService ftpEventService = Mockito.mock(FtpEventService.class);
        ftplet = new FtpHoneypot(ftpEventService).createFtplet();
    }

    @Test
    void alLlegarElPassSeConoceElUserDeLaSesion() throws Exception {
        FtpSession sesion = nuevaSesion();

        enviar(sesion, "USER", "admin");
        enviar(sesion, "PASS", "admin");

        assertEquals("admin", FtpHoneypot.usuarioDeSesion(sesion));
    }

    @Test
    void unSegundoUserSustituyeAlAnterior() throws Exception {
        FtpSession sesion = nuevaSesion();

        enviar(sesion, "USER", "admin");
        enviar(sesion, "USER", "root");
        enviar(sesion, "PASS", "toor");

        assertEquals("root", FtpHoneypot.usuarioDeSesion(sesion));
    }

    @Test
    void dosConexionesAlaVezGuardanCadaUnaSuUser() throws Exception {
        FtpSession sesionA = nuevaSesion();
        FtpSession sesionB = nuevaSesion();

        enviar(sesionA, "USER", "admin");
        enviar(sesionB, "USER", "root");

        assertEquals("admin", FtpHoneypot.usuarioDeSesion(sesionA));
        assertEquals("root", FtpHoneypot.usuarioDeSesion(sesionB));
    }

    @Test
    void alCerrarLaSesionSeOlvidaElUser() throws Exception {
        FtpSession sesion = nuevaSesion();
        enviar(sesion, "USER", "admin");

        ftplet.onDisconnect(sesion);

        assertNull(FtpHoneypot.usuarioDeSesion(sesion));
    }

    @Test
    void unaSesionNuevaNoConservaElUserDeOtra() throws Exception {
        FtpSession anterior = nuevaSesion();
        enviar(anterior, "USER", "admin");
        ftplet.onDisconnect(anterior);

        FtpSession nueva = nuevaSesion();

        assertNull(FtpHoneypot.usuarioDeSesion(nueva));
    }

    private void enviar(FtpSession sesion, String comando, String argumento) throws Exception {
        FtpRequest request = Mockito.mock(FtpRequest.class);
        when(request.getCommand()).thenReturn(comando);
        when(request.getArgument()).thenReturn(argumento);
        ftplet.beforeCommand(sesion, request);
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