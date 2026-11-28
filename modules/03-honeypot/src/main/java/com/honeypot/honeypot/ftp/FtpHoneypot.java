package com.honeypot.honeypot.ftp;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

import org.apache.ftpserver.FtpServer;
import org.apache.ftpserver.FtpServerFactory;
import org.apache.ftpserver.ftplet.DefaultFtpReply;
import org.apache.ftpserver.ftplet.DefaultFtplet;
import org.apache.ftpserver.ftplet.FtpException;
import org.apache.ftpserver.ftplet.FtpRequest;
import org.apache.ftpserver.ftplet.FtpSession;
import org.apache.ftpserver.ftplet.Ftplet;
import org.apache.ftpserver.ftplet.FtpletResult;
import org.apache.ftpserver.impl.DefaultFtpHandler;
import org.apache.ftpserver.impl.FtpIoSession;
import org.apache.ftpserver.listener.ListenerFactory;
import org.apache.ftpserver.listener.Listener;
import org.apache.ftpserver.listener.nio.NioListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.honeypot.honeypot.service.FtpEventService;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Component
public class FtpHoneypot {

    private static final Logger log =
            LoggerFactory.getLogger(FtpHoneypot.class);
    private static final Set<String> COMMANDS_ALLOWED_BEFORE_LOGIN =
            Set.of("USER", "PASS", "AUTH", "QUIT", "PROT", "PBSZ");
    static final String USUARIO_SESION = "honeypot.ftp.usuario";
    static final String IP_REAL = "honeypot.ftp.ipReal";
    private static final String CONEXION_REGISTRADA = "honeypot.ftp.conexionRegistrada";
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    @Value("${honeypot.ftp.port:2121}")
    private int port;

    private FtpServer server;
    private final FtpEventService ftpEventService;

    public FtpHoneypot(FtpEventService ftpEventService) {
        this.ftpEventService = ftpEventService;
    }

    @PostConstruct
    public void start() {

        try {
            FtpServerFactory serverFactory = new FtpServerFactory();

            ListenerFactory listenerFactory = new ListenerFactory();
            listenerFactory.setPort(port);

            Listener listener = listenerFactory.createListener();
            installPreAuthenticationHandler(listener);
            serverFactory.addListener("default", listener);

            // Comportamiento personalizado del Honeypot
            Map<String, Ftplet> ftplets = new HashMap<>();

            ftplets.put("honeypot", createFtplet());

            serverFactory.setFtplets(ftplets);

            server = serverFactory.createServer();
            server.start();

            log.info("FTP HONEYPOT iniciado en puerto {}", port);

        } catch (Exception e) {
            log.error("Error iniciando FTP Honeypot", e);
        }
    }

    private void installPreAuthenticationHandler(Listener listener)
            throws ReflectiveOperationException {

        if (!(listener instanceof NioListener)) {
            throw new IllegalStateException(
                    "El listener FTP no es compatible con el registro previo a autenticación"
            );
        }

        // FTPServer rechaza comandos no autenticados antes de invocar el Ftplet.
        Field handlerField = NioListener.class.getDeclaredField("handler");
        handlerField.setAccessible(true);
        handlerField.set(listener, new PreAuthenticationFtpHandler());
    }

    private void registrarComando(
            String sourceIp,
            FtpRequest request,
            String command) {
        registrarComando(sourceIp, request, command, null);
    }

    private void registrarComando(
            String sourceIp,
            FtpRequest request,
            String command,
            String usuarioSesion) {

        try {
            ftpEventService.registrarComando(
                    sourceIp,
                    command,
                    request.getArgument(),
                    usuarioSesion
            );
        } catch (RuntimeException e) {
            log.error(
                    "No se pudo registrar el comando FTP {}",
                    command,
                    e
            );
        }
    }

    // Al crear la sesión aún no se sabe la IP real: la manda el proxy en la primera línea.
    // Un escaneo no manda nada más, por eso también se mira al cerrar
    private void registrarConexion(FtpSession session) {
        if (session.getAttribute(CONEXION_REGISTRADA) != null) {
            return;
        }
        session.setAttribute(CONEXION_REGISTRADA, Boolean.TRUE);
        try {
            ftpEventService.registrarConexion(ipCliente(session));
        } catch (RuntimeException e) {
            log.error("No se pudo registrar la conexion al servicio FTP", e);
        }
    }

    // Cabecera del protocolo PROXY: "PROXY TCP4 <ip origen> <ip destino> <puerto> <puerto>"
    static void guardarIpReal(FtpSession session, String argumento) {
        if (argumento == null) {
            return;
        }
        String[] partes = argumento.trim().split(" ");
        if (partes.length < 2 || !partes[0].startsWith("TCP")) {
            return;
        }
        String ip = partes[1];
        if (!IPV4.matcher(ip).matches() && !ip.contains(":")) {
            return;
        }
        try {
            session.setAttribute(IP_REAL, InetAddress.getByName(ip).getHostAddress());
        } catch (UnknownHostException e) {
            log.warn("Cabecera PROXY con una IP no valida: {}", ip);
        }
    }

    static String ipCliente(FtpSession session) {
        Object ip = session.getAttribute(IP_REAL);
        if (ip instanceof String) {
            return (String) ip;
        }
        InetSocketAddress clientAddress = session.getClientAddress();
        return clientAddress == null ? null : clientAddress.getAddress().getHostAddress();
    }

    private final class PreAuthenticationFtpHandler
            extends DefaultFtpHandler {

        @Override
        public void sessionClosed(FtpIoSession session) throws Exception {
            registrarConexion(session.getFtpletSession());
            super.sessionClosed(session);
        }

        @Override
        public void messageReceived(FtpIoSession session, FtpRequest request)
                throws Exception {

            FtpSession ftpSession = session.getFtpletSession();
            String command = request.getCommand().toUpperCase(Locale.ROOT);

            // Solo vale como primera línea, que es la que manda el nginx
            if ("PROXY".equals(command)
                    && ftpSession.getAttribute(CONEXION_REGISTRADA) == null) {
                guardarIpReal(ftpSession, request.getArgument());
                registrarConexion(ftpSession);
                return;
            }
            registrarConexion(ftpSession);

            if (!session.isLoggedIn()
                    && !COMMANDS_ALLOWED_BEFORE_LOGIN.contains(command)) {
                registrarComando(
                        ipCliente(ftpSession),
                        request,
                        command
                );
                session.write(new DefaultFtpReply(530, "Not logged in."));
                return;
            }

            super.messageReceived(session, request);
        }
    }

    static String usuarioDeSesion(FtpSession session) {
        Object usuario = session.getAttribute(USUARIO_SESION);
        return usuario instanceof String ? (String) usuario : null;
    }

    Ftplet createFtplet() {

        return new DefaultFtplet() {

            @Override
            public FtpletResult beforeCommand(
                    FtpSession session,
                    FtpRequest request)
                    throws FtpException, IOException {

                String command =
                        request.getCommand().toUpperCase(Locale.ROOT);

                // al PASS se le pasa el USER guardado en esta sesión
                String usuarioSesion = "PASS".equals(command)
                        ? usuarioDeSesion(session)
                        : null;

                registrarComando(
                        ipCliente(session),
                        request,
                        command,
                        usuarioSesion
                );

                // Usuario: permitir continuar hasta la autenticación
                if ("USER".equals(command)) {

                    //recordar el USER de esta sesión (sustituye al anterior)
                    String usuario = request.getArgument();
                    if (usuario == null || usuario.isBlank()) {
                        session.removeAttribute(USUARIO_SESION);
                    } else {
                        session.setAttribute(USUARIO_SESION, usuario);
                    }

                    session.write(
                            new DefaultFtpReply(
                                    331,
                                    "User name okay, need password."
                            )
                    );

                    return FtpletResult.SKIP;
                }

                // Contraseña: rechazar autenticación
                if ("PASS".equals(command)) {

                    session.write(
                            new DefaultFtpReply(
                                    530,
                                    "Authentication failed."
                            )
                    );

                    return FtpletResult.SKIP;
                }

                if (!session.isLoggedIn()
                        && ("LIST".equals(command)
                        || "CWD".equals(command)
                        || "RETR".equals(command))) {

                    session.write(
                            new DefaultFtpReply(
                                    530,
                                    "Not logged in."
                            )
                    );

                    return FtpletResult.SKIP;
                }

                return FtpletResult.DEFAULT;
            }

            @Override
            public FtpletResult onDisconnect(FtpSession session)
                    throws FtpException, IOException {

                //al cerrar la conexión se olvida el USER guardado
                session.removeAttribute(USUARIO_SESION);
                return FtpletResult.DEFAULT;
            }
        };
    }

    @PreDestroy
    public void stop() {

        if (server != null) {
            server.stop();
            log.info("FTP HONEYPOT detenido");
        }
    }
}