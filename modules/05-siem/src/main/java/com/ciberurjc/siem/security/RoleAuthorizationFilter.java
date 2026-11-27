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

/**
 * Aplica la matriz de permisos (SEM-142 / HU19) después de autenticar con G1 (SEM-133 / HU18)
 * y antes de los controladores: una petición sin permiso no valida, guarda ni consulta nada.
 * Contrato: modules/05-siem/contract/roles-permissions.md.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 2) // justo después de IdentityAuthenticationFilter
public class RoleAuthorizationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RoleAuthorizationFilter.class);

    static final String FORBIDDEN_BODY =
            "{\"error\":{\"code\":\"FORBIDDEN\",\"message\":\"This account is not allowed to perform this operation\"}}";

    private final AccessPolicy policy;

    public RoleAuthorizationFilter(AccessPolicy policy) {
        this.policy = policy;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Igual que en IdentityAuthenticationFilter: solo GET/HEAD /health es público.
        String method = request.getMethod();
        return ("GET".equals(method) || "HEAD".equals(method)) && "/health".equals(path(request));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String method = request.getMethod();
        String path = path(request);
        Object attribute = request.getAttribute(AuthenticatedIdentity.REQUEST_ATTRIBUTE);
        AuthenticatedIdentity identity = attribute instanceof AuthenticatedIdentity id ? id : null;

        if (identity == null || !policy.canAccess(identity, method, path)) {
            log.info("Authorization denied for {} {}: user={} role={}", method, path,
                    identity == null ? "" : safe(identity.username()),
                    identity == null ? "" : safe(identity.role()));
            writeForbidden(response);
            return;
        }
        chain.doFilter(request, response);
    }

    /**
     * Ruta normalizada por el contenedor (sin "..", sin context path), la misma que usa Spring
     * para elegir el controlador. Así no se puede saltar la matriz con rutas como /alerts/x/../../events.
     */
    private static String path(HttpServletRequest request) {
        String servletPath = request.getServletPath() == null ? "" : request.getServletPath();
        String pathInfo = request.getPathInfo() == null ? "" : request.getPathInfo();
        String path = servletPath + pathInfo;
        return path.isEmpty() ? "/" : path;
    }

    private static String safe(String value) {
        return value == null ? "" : value.replaceAll("[\\p{Cntrl}]", "_");
    }

    static void writeForbidden(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(FORBIDDEN_BODY);
    }
}