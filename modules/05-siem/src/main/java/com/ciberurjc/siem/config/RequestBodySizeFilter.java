package com.ciberurjc.siem.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Rejects request bodies larger than the configured limit. Declared lengths are
 * rejected before reading; chunked bodies are cut off while they are read.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestBodySizeFilter extends OncePerRequestFilter {

    static final String TOO_LARGE_BODY =
        "{\"error\":{\"code\":\"PAYLOAD_TOO_LARGE\",\"message\":\"The request body exceeds the maximum allowed size\"}}";

    private final long maxBytes;

    public RequestBodySizeFilter(@Value("${siem.events.max-body-bytes:65536}") long maxBytes) {
        if (maxBytes < 1) {
            throw new IllegalArgumentException("siem.events.max-body-bytes must be at least 1");
        }
        this.maxBytes = maxBytes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getContentLengthLong() > maxBytes) {
            writeTooLarge(response);
            return;
        }
        chain.doFilter(new LimitedBodyRequest(request, maxBytes), response);
    }

    public static void writeTooLarge(HttpServletResponse response) throws IOException {
        response.setStatus(413);
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(TOO_LARGE_BODY);
    }

    private static final class LimitedBodyRequest extends HttpServletRequestWrapper {
        private final long maxBytes;
        private ServletInputStream stream;

        LimitedBodyRequest(HttpServletRequest request, long maxBytes) {
            super(request);
            this.maxBytes = maxBytes;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                stream = new LimitedInputStream(super.getInputStream(), maxBytes);
            }
            return stream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            String encoding = getCharacterEncoding();
            Charset charset = encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }

    private static final class LimitedInputStream extends ServletInputStream {
        private final ServletInputStream delegate;
        private final long maxBytes;
        private long readBytes;

        LimitedInputStream(ServletInputStream delegate, long maxBytes) {
            this.delegate = delegate;
            this.maxBytes = maxBytes;
        }

        @Override
        public int read() throws IOException {
            int value = delegate.read();
            if (value != -1) {
                count(1);
            }
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int read = delegate.read(buffer, offset, length);
            if (read > 0) {
                count(read);
            }
            return read;
        }

        private void count(int bytes) throws RequestBodyTooLargeException {
            readBytes += bytes;
            if (readBytes > maxBytes) {
                throw new RequestBodyTooLargeException();
            }
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            delegate.setReadListener(listener);
        }
    }
}
