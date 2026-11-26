package com.ciberurjc.siem;

import com.ciberurjc.siem.security.AuthenticatedIdentity;
import com.ciberurjc.siem.security.IdentityUnavailableException;
import com.ciberurjc.siem.security.IdentityValidator;
import com.ciberurjc.siem.security.UnauthenticatedException;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sustituye a G1 en los tests (solo existe en src/test). Spring lo detecta al escanear el paquete
 * y, por ser @Primary, el filtro lo usa en lugar de G1IdentityValidator.
 * Cuenta las llamadas para comprobar cuándo no se consulta a Identidad.
 */
@Component
@Primary
public class TestIdentityValidator implements IdentityValidator {

    private final AtomicInteger calls = new AtomicInteger();

    @Override
    public AuthenticatedIdentity validate(String token) {
        calls.incrementAndGet();
        if (TestIdentity.VALID_TOKEN.equals(token)) {
            // Identidad sin restricciones de rol (ver TestAccessPolicy): la usan los tests que
            // prueban otras funciones del SIEM y no la autorización.
            return new AuthenticatedIdentity(TestIdentity.UNRESTRICTED_USERNAME, "analista", 1L);
        }
        if (token.startsWith(TestIdentity.AS_PREFIX)) {
            // SEM-142: "test-as.<cuenta>.<rol>" simula la identidad que devolvería G1.
            String identity = token.substring(TestIdentity.AS_PREFIX.length());
            int dot = identity.lastIndexOf('.');
            if (dot > 0) {
                return new AuthenticatedIdentity(identity.substring(0, dot), identity.substring(dot + 1), 2L);
            }
        }
        if (TestIdentity.UNAVAILABLE_TOKEN.equals(token)) {
            throw new IdentityUnavailableException("Identity test stub unavailable", true);
        }
        throw new UnauthenticatedException("Identity test stub rejected the token");
    }

    public int calls() {
        return calls.get();
    }

    public void reset() {
        calls.set(0);
    }
}
