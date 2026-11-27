package com.ciberurjc.siem.security;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Matriz de permisos de roles-permissions.md (SEM-141), aplicada en SEM-142.
 * Denegación por defecto: cualquier operación, rol o cuenta que no aparezca aquí se rechaza.
 */
@Component
public class RoleAccessPolicy implements AccessPolicy {

    static final String SERVICE_ROLE = "servicio";
    static final String ANALYST_ROLE = "analista";
    static final String ADMIN_ROLE = "admin";
    static final String SOAR_ACCOUNT = "svc-soar";

    /** Cuentas productoras y el único {@code source} que puede publicar cada una. */
    static final Map<String, String> PRODUCER_SOURCES = Map.of(
            "svc-ids", "ids",
            "svc-honeypot", "honeypot",
            "svc-escaner", "scanner",
            "svc-pentesting", "pentesting");

    private static final Set<String> HUMAN_ROLES = Set.of(ANALYST_ROLE, ADMIN_ROLE);

    /** /alerts/{id}: exactamente un segmento después de /alerts/. */
    private static final Pattern ALERT_DETAIL = Pattern.compile("^/alerts/[^/]+$");

    @Override
    public boolean canAccess(AuthenticatedIdentity identity, String method, String path) {
        if (identity == null || method == null || path == null) {
            return false;
        }
        boolean read = "GET".equals(method) || "HEAD".equals(method);

        if ("POST".equals(method) && "/events".equals(path)) {
            return isProducer(identity);
        }
        if (read && "/events".equals(path)) {
            return isHuman(identity);
        }
        if (read && ("/alerts".equals(path) || ALERT_DETAIL.matcher(path).matches())) {
            return isHuman(identity) || isAccount(identity, SOAR_ACCOUNT);
        }
        return false;
    }

    @Override
    public boolean canPublish(AuthenticatedIdentity identity, String source) {
        if (identity == null || source == null || !isProducer(identity)) {
            return false;
        }
        return source.equals(PRODUCER_SOURCES.get(identity.username()));
    }

    private static boolean isProducer(AuthenticatedIdentity identity) {
        return SERVICE_ROLE.equals(identity.role()) && PRODUCER_SOURCES.containsKey(identity.username());
    }

    private static boolean isHuman(AuthenticatedIdentity identity) {
        return HUMAN_ROLES.contains(identity.role());
    }

    private static boolean isAccount(AuthenticatedIdentity identity, String account) {
        return SERVICE_ROLE.equals(identity.role()) && account.equals(identity.username());
    }
}