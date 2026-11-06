
package com.honeypot.honeypot.ftp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

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

class FtpHoneypotTest {

    private FtpEventService ftpEventService;
    private FtpHoneypot ftpHoneypot;
    private FtpSession session;
    private FtpRequest request;
    private Ftplet ftplet;

    @BeforeEach
    void setUp() {

        ftpEventService = Mockito.mock(FtpEventService.class);
        ftpHoneypot = new FtpHoneypot(ftpEventService);

        session = Mockito.mock(FtpSession.class);
        request = Mockito.mock(FtpRequest.class);

        when(session.isLoggedIn()).thenReturn(false);
        when(session.getClientAddress())
                .thenReturn(new InetSocketAddress("127.0.0.1", 12345));

        ftplet = ftpHoneypot.createFtplet();
    }

    @Test
    void comandosSinLoginDevuelven530YSeRegistran() throws Exception {

        List<String> commands = List.of("LIST", "CWD", "RETR");
        List<FtpletResult> results = new ArrayList<>();

        for (String command : commands) {
            when(request.getCommand()).thenReturn(command);
            when(request.getArgument()).thenReturn("test");
            results.add(ftplet.beforeCommand(session, request));
        }

        ArgumentCaptor<FtpReply> replyCaptor =
                ArgumentCaptor.forClass(FtpReply.class);
        verify(session, times(3)).write(replyCaptor.capture());

        ArgumentCaptor<String> commandCaptor =
                ArgumentCaptor.forClass(String.class);
        verify(ftpEventService, times(3)).registrarComando(
                eq("127.0.0.1"),
                commandCaptor.capture(),
                eq("test")
        );

        assertEquals(
                List.of(FtpletResult.SKIP, FtpletResult.SKIP, FtpletResult.SKIP),
                results
        );
        assertEquals(
                List.of(530, 530, 530),
                replyCaptor.getAllValues().stream().map(FtpReply::getCode).toList()
        );
        assertEquals(commands, commandCaptor.getAllValues());
    }
}
