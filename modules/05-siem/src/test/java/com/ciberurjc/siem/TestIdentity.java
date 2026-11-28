package com.ciberurjc.siem;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * Utilidades de test para la autenticación del SIEM (SEM-133).
 * Los tokens solo los entiende {@link TestIdentityValidator}; no son credenciales reales.
 */
public final class TestIdentity {

    /** Token que el validador de test acepta como analista. */
    public static final String VALID_TOKEN = "test-valid-token";
    /** Token con el que el validador de test simula que Identidad (G1) no responde. */
    public static final String UNAVAILABLE_TOKEN = "test-identity-unavailable";
    public static final String BEARER = "Bearer " + VALID_TOKEN;

    private TestIdentity() {
    }

    /**
     * HttpClient que añade "Authorization: Bearer test-valid-token" a las peticiones que no llevan
     * Authorization. Lo usan los tests anteriores a SEM-133, que prueban otras funciones del SIEM.
     */
    public static HttpClient authenticatedClient() {
        return new AuthenticatedClient(HttpClient.newHttpClient());
    }

    static HttpRequest withToken(HttpRequest request) {
        if (request.headers().firstValue("Authorization").isPresent()) {
            return request;
        }
        return HttpRequest.newBuilder(request, (name, value) -> true)
                .header("Authorization", BEARER)
                .build();
    }

    private static final class AuthenticatedClient extends HttpClient {
        private final HttpClient delegate;

        AuthenticatedClient(HttpClient delegate) {
            this.delegate = delegate;
        }

        @Override
        public Optional<CookieHandler> cookieHandler() {
            return delegate.cookieHandler();
        }

        @Override
        public Optional<Duration> connectTimeout() {
            return delegate.connectTimeout();
        }

        @Override
        public Redirect followRedirects() {
            return delegate.followRedirects();
        }

        @Override
        public Optional<ProxySelector> proxy() {
            return delegate.proxy();
        }

        @Override
        public SSLContext sslContext() {
            return delegate.sslContext();
        }

        @Override
        public SSLParameters sslParameters() {
            return delegate.sslParameters();
        }

        @Override
        public Optional<Authenticator> authenticator() {
            return delegate.authenticator();
        }

        @Override
        public Version version() {
            return delegate.version();
        }

        @Override
        public Optional<Executor> executor() {
            return delegate.executor();
        }

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
                throws IOException, InterruptedException {
            return delegate.send(withToken(request), handler);
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                HttpResponse.BodyHandler<T> handler) {
            return delegate.sendAsync(withToken(request), handler);
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                HttpResponse.BodyHandler<T> handler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
            return delegate.sendAsync(withToken(request), handler, pushPromiseHandler);
        }
    }
}
