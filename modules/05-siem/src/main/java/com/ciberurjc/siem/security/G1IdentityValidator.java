package com.ciberurjc.siem.security;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Valida tokens llamando a GET /auth/validate del Módulo 1 (G1).
 * El SIEM no decodifica el JWT ni guarda validaciones en caché (contrato identity-auth.md, SEM-132).
 */
@Component
public class G1IdentityValidator implements IdentityValidator {

    private static final Logger log = LoggerFactory.getLogger(G1IdentityValidator.class);

    /** null si IDENTITY_URL no está configurada: entonces se responde 503 (fail-closed). */
    private final URI validateUri;
    private final Duration timeout;
    private final HttpClient httpClient;
    private final ObjectMapper mapper;

    public G1IdentityValidator(
            @Value("${siem.identity.url:}") String identityUrl,
            @Value("${siem.identity.connect-timeout-ms:1000}") long connectTimeoutMs,
            @Value("${siem.identity.timeout-ms:2000}") long timeoutMs,
            ObjectMapper mapper) {
        this.validateUri = buildValidateUri(identityUrl);
        this.timeout = Duration.ofMillis(timeoutMs);
        this.mapper = mapper;
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        if (validateUri == null) {
            log.warn("IDENTITY_URL no está configurada: las operaciones protegidas responderán 503");
        }
    }

    @Override
    public AuthenticatedIdentity validate(String token) {
        if (validateUri == null) {
            throw new IdentityUnavailableException("IDENTITY_URL is not configured", false);
        }

        HttpResponse<byte[]> response;
        try {
            HttpRequest request = HttpRequest.newBuilder(validateUri)
                    .timeout(timeout)
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            // Timeout, conexión rechazada o cortada: G1 no está disponible.
            throw new IdentityUnavailableException(
                    "Identity request failed: " + e.getClass().getSimpleName(), true, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IdentityUnavailableException("Identity request interrupted", true, e);
        }

        int status = response.statusCode();
        if (status == 401) {
            throw new UnauthenticatedException("Identity rejected the token");
        }
        if (status >= 500) {
            throw new IdentityUnavailableException("Identity answered " + status, true);
        }
        if (status != 200) {
            throw new IdentityUnavailableException("Unexpected identity status " + status, false);
        }
        return parse(response.body());
    }

    private AuthenticatedIdentity parse(byte[] body) {
        ValidateResponse result;
        try {
            result = mapper.readValue(body, ValidateResponse.class);
        } catch (JacksonException e) {
            throw new IdentityUnavailableException("Unreadable identity response", false);
        }
        if (result == null
                || !Boolean.TRUE.equals(result.valid())
                || isBlank(result.username())
                || isBlank(result.role())) {
            throw new IdentityUnavailableException("Incompatible identity response", false);
        }
        return new AuthenticatedIdentity(result.username(), result.role(), result.userId());
    }

    private static URI buildValidateUri(String identityUrl) {
        if (identityUrl == null || identityUrl.isBlank()) {
            return null;
        }
        String base = identityUrl.strip();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        URI uri = URI.create(base + "/auth/validate");
        boolean httpScheme = "http".equals(uri.getScheme()) || "https".equals(uri.getScheme());
        if (!httpScheme || uri.getHost() == null) {
            throw new IllegalStateException("IDENTITY_URL must be an http(s) URL with a host");
        }
        return uri;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** Respuesta 200 de G1: {"valid": true, "user_id": 1, "username": "...", "role": "..."}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record ValidateResponse(
            Boolean valid,
            String username,
            String role,
            @JsonProperty("user_id") Long userId) {
    }
}
