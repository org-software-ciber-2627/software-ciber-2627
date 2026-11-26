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
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Component
public class FtpHoneypot {

    private static final Logger log =
            LoggerFactory.getLogger(FtpHoneypot.class);
    private static final Set<String> COMMANDS_ALLOWED_BEFORE_LOGIN =
            Set.of("USER", "PASS", "AUTH", "QUIT", "PROT", "PBSZ");
    static final String USUARIO_SESION = "honeypot.ftp.usuario";

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
            InetSocketAddress clientAddress,
            FtpRequest request,
            String command) {
        registrarComando(clientAddress, request, command, null);
    }

    private void registrarComando(
            InetSocketAddress clientAddress,
            FtpRequest request,
            String command,
            String usuarioSesion) {

        try {
            String sourceIp = clientAddress
                    .getAddress()
                    .getHostAddress();

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

    private final class PreAuthenticationFtpHandler
            extends DefaultFtpHandler {

        @Override
        public void sessionCreated(FtpIoSession session) throws Exception {
            InetSocketAddress clientAddress = session.getFtpletSession().getClientAddress();
            try {
                ftpEventService.registrarConexion(clientAddress.getAddress().getHostAddress());
            } catch (RuntimeException e) {
                log.error("No se pudo registrar la conexion al servicio FTP", e);
            }
            super.sessionCreated(session);
        }

        @Override
        public void messageReceived(FtpIoSession session, FtpRequest request)
                throws Exception {

            String command = request.getCommand().toUpperCase(Locale.ROOT);

            if (!session.isLoggedIn()
                    && !COMMANDS_ALLOWED_BEFORE_LOGIN.contains(command)) {
                registrarComando(
                        session.getFtpletSession().getClientAddress(),
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
                        session.getClientAddress(),
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