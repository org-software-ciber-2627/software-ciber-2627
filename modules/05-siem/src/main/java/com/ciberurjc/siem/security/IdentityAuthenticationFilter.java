package com.ciberurjc.siem.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Exige un token Bearer validado por G1 en todas las rutas salvo GET /health (SEM-133 / HU18).
 * Se ejecuta antes de los controladores: una petición rechazada no valida, guarda ni genera alertas.
 * Fail-closed: si no se puede confirmar la identidad, no se concede acceso.
 * Contrato: modules/05-siem/contract/identity-auth.md.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1) // justo después de RequestBodySizeFilter
public class IdentityAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(IdentityAuthenticationFilter.class);

    /** "Bearer <token68>" (RFC 6750). El esquema no distingue mayúsculas. */
    private static final Pattern BEARER =
            Pattern.compile("^Bearer +([A-Za-z0-9\\-._~+/]+=*)$", Pattern.CASE_INSENSITIVE);
    private static final int MAX_HEADER_LENGTH = 8192;

    static final String UNAUTHENTICATED_BODY =
            "{\"error\":{\"code\":\"UNAUTHENTICATED\",\"message\":\"Missing, invalid, expired or revoked token\"}}";
    static final String IDENTITY_UNAVAILABLE_BODY =
            "{\"error\":{\"code\":\"IDENTITY_UNAVAILABLE\",\"message\":\"The identity service is not available\"}}";
    static final String RETRY_AFTER_SECONDS = "30";

    private final IdentityValidator validator;

    public IdentityAuthenticationFilter(IdentityValidator validator) {
        this.validator = validator;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Solo GET /health es público. Cualquier otra ruta, conocida o no, exige identidad.
        String method = request.getMethod();
        return ("GET".equals(method) || "HEAD".equals(method)) && "/health".equals(path(request));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String operation = request.getMethod() + " " + path(request);

        String token = bearerToken(request);
        if (token == null) {
            // Sin cabecera o con formato incorrecto: no se llama a G1.
            log.info("Authentication rejected for {}: missing or malformed Authorization header", operation);
            writeUnauthenticated(response);
            return;
        }

        AuthenticatedIdentity identity;
        try {
            identity = validator.validate(token);
        } catch (UnauthenticatedException e) {
            log.info("Authentication rejected for {}: token rejected by identity service", operation);
            writeUnauthenticated(response);
            return;
        } catch (IdentityUnavailableException e) {
            log.warn("Authentication unavailable for {}: {}", operation, e.getMessage());
            writeIdentityUnavailable(response, e.retryLater());
            return;
        } catch (RuntimeException e) {
            // Cualquier fallo inesperado también deniega el acceso.
            log.error("Authentication failed unexpectedly for {}: {}", operation, e.getClass().getSimpleName());
            writeIdentityUnavailable(response, false);
            return;
        }

        log.info("Authenticated {} as user={} role={}", operation, safe(identity.username()), safe(identity.role()));
        request.setAttribute(AuthenticatedIdentity.REQUEST_ATTRIBUTE, identity);
        chain.doFilter(request, response);
    }

    /** Devuelve el token de una única cabecera "Authorization: Bearer <token>", o null. */
    private static String bearerToken(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders("Authorization");
        if (headers == null || !headers.hasMoreElements()) {
            return null;
        }
        String value = headers.nextElement();
        if (headers.hasMoreElements()) {
            return null; // varias cabeceras Authorization: ambiguo, se rechaza
        }
        if (value == null || value.length() > MAX_HEADER_LENGTH) {
            return null;
        }
        Matcher matcher = BEARER.matcher(value.strip());
        return matcher.matches() ? matcher.group(1) : null;
    }

    /** Ruta sin el context path (por ejemplo /siem/health -> /health). */
    private static String path(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        return context != null && !context.isEmpty() && uri.startsWith(context)
                ? uri.substring(context.length())
                : uri;
    }

    /** Evita inyección en logs con valores devueltos por G1. */
    private static String safe(String value) {
        return value == null ? "" : value.replaceAll("[\\p{Cntrl}]", "_");
    }

    private static void writeUnauthenticated(HttpServletResponse response) throws IOException {
        response.setHeader("WWW-Authenticate", "Bearer");
        writeError(response, HttpServletResponse.SC_UNAUTHORIZED, UNAUTHENTICATED_BODY);
    }

    private static void writeIdentityUnavailable(HttpServletResponse response, boolean retryLater)
            throws IOException {
        if (retryLater) {
            response.setHeader("Retry-After", RETRY_AFTER_SECONDS);
        }
        writeError(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE, IDENTITY_UNAVAILABLE_BODY);
    }

    private static void writeError(HttpServletResponse response, int status, String body) throws IOException {
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(body);
    }
}
