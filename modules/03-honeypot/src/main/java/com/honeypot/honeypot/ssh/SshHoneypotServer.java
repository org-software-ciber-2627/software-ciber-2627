package com.honeypot.honeypot.ssh;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
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

    @Value("${honeypot.ssh.port:2222}")
    private int port;

    @Value("${honeypot.ssh.version:OpenSSH_8.9p1 Ubuntu-3ubuntu0.6}")
    private String serverVersion;

    @Value("${honeypot.ssh.hostkey:hostkey.ser}")
    private String hostKeyPath;

    private final List<SshAttemptListener> listeners;
    private SshServer sshd;

    public SshHoneypotServer(List<SshAttemptListener> listeners) {
        this.listeners = listeners;
    }

    @PostConstruct
    public void start() throws IOException {
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get(hostKeyPath)));
        CoreModuleProperties.SERVER_IDENTIFICATION.set(sshd, serverVersion);

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