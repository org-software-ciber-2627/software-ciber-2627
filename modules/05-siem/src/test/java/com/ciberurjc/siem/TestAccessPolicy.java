package com.ciberurjc.siem;

import com.ciberurjc.siem.security.AccessPolicy;
import com.ciberurjc.siem.security.AuthenticatedIdentity;
import com.ciberurjc.siem.security.RoleAccessPolicy;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

/**
 * Solo existe en src/test. Aplica la matriz real (RoleAccessPolicy) a todas las identidades salvo a la
 * de TestIdentity.VALID_TOKEN, que usan los tests anteriores a SEM-142 para probar otras funciones
 * (por ejemplo, publicar eventos de cualquier origen y leerlos después con el mismo token).
 */
@Component
@Primary
public class TestAccessPolicy implements AccessPolicy {

    private final RoleAccessPolicy matrix = new RoleAccessPolicy();

    @Override
    public boolean canAccess(AuthenticatedIdentity identity, String method, String path) {
        return unrestricted(identity) || matrix.canAccess(identity, method, path);
    }

    @Override
    public boolean canPublish(AuthenticatedIdentity identity, String source) {
        return unrestricted(identity) || matrix.canPublish(identity, source);
    }

    private static boolean unrestricted(AuthenticatedIdentity identity) {
        return identity != null && TestIdentity.UNRESTRICTED_USERNAME.equals(identity.username());
    }
}