package com.honeypot.honeypot.ssh;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.contrib.server.session.proxyprotocol.ProxyProtocolAcceptor;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import com.honeypot.honeypot.service.DetectorEscaneoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;

@Component
public class SshHoneypotServer {

    private static final Logger log = LoggerFactory.getLogger(SshHoneypotServer.class);
    private static final AttributeRepository.AttributeKey<Boolean> CONTACTO_REGISTRADO =
            new AttributeRepository.AttributeKey<>();

    @Value("${honeypot.ssh.port:2222}")
    private int port;

    @Value("${honeypot.ssh.version:OpenSSH_8.9p1 Ubuntu-3ubuntu0.6}")
    private String serverVersion;

    @Value("${honeypot.ssh.hostkey:hostkey.ser}")
    private String hostKeyPath;

    private final List<SshAttemptListener> listeners;
    private final DetectorEscaneoService detectorEscaneoService;
    private SshServer sshd;

    public SshHoneypotServer(
            List<SshAttemptListener> listeners,
            DetectorEscaneoService detectorEscaneoService
    ) {
        this.listeners = listeners;
        this.detectorEscaneoService = detectorEscaneoService;
    }

    @PostConstruct
    public void start() throws IOException {
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get(hostKeyPath)));
        CoreModuleProperties.SERVER_IDENTIFICATION.set(sshd, serverVersion);
        sshd.setServerProxyAcceptor(new ProxyProtocolAcceptor());
        // Al crear la sesión todavía hay la IP del proxy. Un escaneo no manda saludo, por eso también al cerrar
        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionPeerIdentificationReceived(Session session, String version, List<String> extraLines) {
                registrarContacto(session);
            }

            @Override
            public void sessionClosed(Session session) {
                registrarContacto(session);
            }
        });

        // Contraseña (también cubre keyboard-interactive, que MINA delega aquí)
        sshd.setPasswordAuthenticator((username, password, session) -> {
            notifyListeners(buildAttempt(session, username,
                    SshAttemptData.AuthMethod.PASSWORD, password, null));
            return false;
        });

        // Clave pública: se registra la huella y se rechaza
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            notifyListeners(buildAttempt(session, username,
                    SshAttemptData.AuthMethod.PUBLIC_KEY, null, KeyUtils.getFingerPrint(key)));
            return false;
        });

        sshd.start();
        log.info("Honeypot SSH escuchando en el puerto {}", port);
    }

    private void registrarContacto(Session session) {
        if (session.getAttribute(CONTACTO_REGISTRADO) != null) {
            return;
        }
        session.setAttribute(CONTACTO_REGISTRADO, Boolean.TRUE);
        if (session instanceof ServerSession serverSession
                && serverSession.getClientAddress() instanceof InetSocketAddress inet) {
            detectorEscaneoService.registrarContacto(
                    inet.getAddress().getHostAddress(), "honeypot-ssh", Instant.now());
        }
    }

    private SshAttemptData buildAttempt(ServerSession session, String username,
                                        SshAttemptData.AuthMethod method,
                                        String password, String fingerprint) {
        String ip = null;
        Integer clientPort = null;
        SocketAddress address = session.getClientAddress();
        if (address instanceof InetSocketAddress inet) {
            ip = inet.getAddress().getHostAddress();
            clientPort = inet.getPort();
        }
        return new SshAttemptData(ip, clientPort, Instant.now(), username,
                method, password, fingerprint, session.getClientVersion());
    }

    private void notifyListeners(SshAttemptData attempt) {
        for (SshAttemptListener listener : listeners) {
            try {
                listener.onAttempt(attempt);
            } catch (Exception e) {
                // Un fallo al registrar nunca debe cambiar el comportamiento del señuelo
                log.error("Error procesando intento SSH en {}", listener.getClass().getSimpleName(), e);
            }
        }
    }

    @PreDestroy
    public void stop() throws IOException {
        if (sshd != null) {
            sshd.stop();
        }
    }
}