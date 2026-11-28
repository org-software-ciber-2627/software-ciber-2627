package com.honeypot.honeypot.ftp;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

import com.honeypot.honeypot.service.FtpEventService;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class FtpHoneypotProxyTest {

    private FtpEventService ftpEventService;
    private FtpHoneypot ftpHoneypot;
    private int puerto;

    @BeforeEach
    void arrancar() throws IOException {
        try (ServerSocket libre = new ServerSocket(0)) {
            puerto = libre.getLocalPort();
        }
        ftpEventService = mock(FtpEventService.class);
        ftpHoneypot = new FtpHoneypot(ftpEventService);
        ReflectionTestUtils.setField(ftpHoneypot, "port", puerto);
        ftpHoneypot.start();
    }

    @AfterEach
    void parar() {
        ftpHoneypot.stop();
    }

    // HP-122: detrás del proxy la conexión y los comandos se guardan con la IP de la cabecera PROXY
    @Test
    void usaLaIpDeLaCabeceraProxy() throws IOException {
        try (Socket socket = new Socket("127.0.0.1", puerto)) {
            BufferedReader entrada = lector(socket);
            entrada.readLine();
            enviar(socket, "PROXY TCP4 203.0.113.9 172.21.0.3 51002 2121\r\nUSER root\r\n");

            // A la cabecera no se responde: lo siguiente que llega es la respuesta al USER
            assertTrue(entrada.readLine().startsWith("331"));
            verify(ftpEventService, timeout(5000)).registrarConexion("203.0.113.9");
            verify(ftpEventService, timeout(5000)).registrarComando(eq("203.0.113.9"), eq("USER"), eq("root"), isNull());
        }
        verify(ftpEventService, after(500).times(1)).registrarConexion(any());
    }

    // HP-122: un escaneo que solo abre y cierra la conexión también cuenta, con la IP real
    @Test
    void unEscaneoSinComandosCuentaConLaIpDeLaCabecera() throws IOException {
        try (Socket socket = new Socket("127.0.0.1", puerto)) {
            lector(socket).readLine();
            enviar(socket, "PROXY TCP4 203.0.113.10 172.21.0.3 51003 2121\r\n");
        }

        verify(ftpEventService, timeout(5000)).registrarConexion("203.0.113.10");
    }

    // HP-122: sin cabecera PROXY se sigue usando la IP de la conexión
    @Test
    void sinCabeceraUsaLaIpDeLaConexion() throws IOException {
        try (Socket socket = new Socket("127.0.0.1", puerto)) {
            BufferedReader entrada = lector(socket);
            entrada.readLine();
            enviar(socket, "USER root\r\n");
            entrada.readLine();

            verify(ftpEventService, timeout(5000)).registrarConexion("127.0.0.1");
        }
    }

    // HP-122: una cabecera PROXY que no es la primera línea no cambia la IP
    @Test
    void unaCabeceraProxyTardiaNoCambiaLaIp() throws IOException {
        try (Socket socket = new Socket("127.0.0.1", puerto)) {
            BufferedReader entrada = lector(socket);
            entrada.readLine();
            enviar(socket, "USER root\r\n");
            entrada.readLine();
            enviar(socket, "PROXY TCP4 203.0.113.11 172.21.0.3 51004 2121\r\nUSER admin\r\n");
            entrada.readLine();
            entrada.readLine();

            verify(ftpEventService, timeout(5000)).registrarComando(eq("127.0.0.1"), eq("USER"), eq("admin"), isNull());
        }
    }

    private BufferedReader lector(Socket socket) throws IOException {
        return new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
    }

    private void enviar(Socket socket, String texto) throws IOException {
        OutputStream salida = socket.getOutputStream();
        salida.write(texto.getBytes(StandardCharsets.US_ASCII));
        salida.flush();
    }
}
