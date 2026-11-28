package com.honeypot.honeypot.ssh;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

import com.honeypot.honeypot.service.DetectorEscaneoService;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

class SshHoneypotServerProxyTest {

    @TempDir
    Path carpeta;

    private DetectorEscaneoService detector;
    private SshHoneypotServer servidor;
    private int puerto;

    @BeforeEach
    void arrancar() throws IOException {
        try (ServerSocket libre = new ServerSocket(0)) {
            puerto = libre.getLocalPort();
        }
        detector = mock(DetectorEscaneoService.class);
        servidor = new SshHoneypotServer(List.of(), detector);
        ReflectionTestUtils.setField(servidor, "port", puerto);
        ReflectionTestUtils.setField(servidor, "serverVersion", "OpenSSH_8.9p1");
        ReflectionTestUtils.setField(servidor, "hostKeyPath", carpeta.resolve("hostkey.ser").toString());
        servidor.start();
    }

    @AfterEach
    void parar() throws IOException {
        servidor.stop();
    }

    // HP-122: detrás del proxy se usa la IP que llega en la cabecera PROXY, no la del nginx
    @Test
    void usaLaIpDeLaCabeceraProxy() throws IOException {
        try (Socket socket = new Socket("127.0.0.1", puerto)) {
            enviar(socket, "PROXY TCP4 203.0.113.7 172.21.0.3 51000 2222\r\nSSH-2.0-Prueba\r\n");

            verify(detector, timeout(5000)).registrarContacto(eq("203.0.113.7"), eq("honeypot-ssh"), any());
        }
        verify(detector, after(500).times(1)).registrarContacto(any(), any(), any());
    }

    // HP-122: un escaneo que solo abre y cierra la conexión también cuenta, con la IP real
    @Test
    void unEscaneoSinSaludoSshCuentaConLaIpDeLaCabecera() throws IOException {
        try (Socket socket = new Socket("127.0.0.1", puerto)) {
            enviar(socket, "PROXY TCP4 203.0.113.8 172.21.0.3 51001 2222\r\n");
            // Como hace el nginx: se lee el saludo del servidor antes de cerrar
            leerLinea(socket);
        }

        verify(detector, timeout(5000)).registrarContacto(eq("203.0.113.8"), eq("honeypot-ssh"), any());
    }

    // HP-122: sin cabecera PROXY se sigue usando la IP de la conexión
    @Test
    void sinCabeceraUsaLaIpDeLaConexion() throws IOException {
        try (Socket socket = new Socket("127.0.0.1", puerto)) {
            enviar(socket, "SSH-2.0-Prueba\r\n");

            verify(detector, timeout(5000)).registrarContacto(eq("127.0.0.1"), eq("honeypot-ssh"), any());
        }
    }

    private void leerLinea(Socket socket) throws IOException {
        InputStream entrada = socket.getInputStream();
        int c;
        do {
            c = entrada.read();
        } while (c != -1 && c != '\n');
    }

    private void enviar(Socket socket, String texto) throws IOException {
        OutputStream salida = socket.getOutputStream();
        salida.write(texto.getBytes(StandardCharsets.US_ASCII));
        salida.flush();
    }
}
