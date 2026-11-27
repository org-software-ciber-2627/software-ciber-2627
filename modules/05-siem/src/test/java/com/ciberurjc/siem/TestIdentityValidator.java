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
            return new AuthenticatedIdentity("test-analista", "analista", 1L);
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
