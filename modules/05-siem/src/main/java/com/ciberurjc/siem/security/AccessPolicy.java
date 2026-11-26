package com.ciberurjc.siem.security;

/**
 * Autorización por rol y cuenta del SIEM (SEM-142 / HU19).
 * Contrato: modules/05-siem/contract/roles-permissions.md (SEM-141).
 */
public interface AccessPolicy {

    /**
     * @param identity identidad ya validada por G1 (HU18)
     * @param method   método HTTP (GET, POST...)
     * @param path     ruta sin context path, por ejemplo /alerts/ALERT-1
     * @return true si la cuenta o el rol pueden usar esa operación
     */
    boolean canAccess(AuthenticatedIdentity identity, String method, String path);

    /**
     * @return true si la cuenta puede publicar eventos con ese {@code source}
     */
    boolean canPublish(AuthenticatedIdentity identity, String source);
}