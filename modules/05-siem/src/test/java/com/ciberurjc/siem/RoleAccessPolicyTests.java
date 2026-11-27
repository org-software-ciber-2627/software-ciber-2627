package com.ciberurjc.siem;

import com.ciberurjc.siem.security.AuthenticatedIdentity;
import com.ciberurjc.siem.security.RoleAccessPolicy;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Matriz de roles-permissions.md (SEM-141) sin arrancar Spring (SEM-142). */
class RoleAccessPolicyTests {

    final RoleAccessPolicy policy = new RoleAccessPolicy();

    static AuthenticatedIdentity as(String username, String role) {
        return new AuthenticatedIdentity(username, role, 1L);
    }

    @Test
    void onlyProducerAccountsPublishEvents() {
        for (String producer : new String[] {"svc-ids", "svc-honeypot", "svc-escaner", "svc-pentesting"}) {
            assertTrue(policy.canAccess(as(producer, "servicio"), "POST", "/events"), producer);
        }
        assertFalse(policy.canAccess(as("svc-soar", "servicio"), "POST", "/events"));
        assertFalse(policy.canAccess(as("svc-siem", "servicio"), "POST", "/events"));
        assertFalse(policy.canAccess(as("servicio", "servicio"), "POST", "/events"));
        assertFalse(policy.canAccess(as("ana", "analista"), "POST", "/events"));
        assertFalse(policy.canAccess(as("root", "admin"), "POST", "/events"));
        // Una cuenta productora con un rol que no es "servicio" no publica.
        assertFalse(policy.canAccess(as("svc-ids", "analista"), "POST", "/events"));
    }

    @Test
    void eachProducerPublishesOnlyItsOwnSource() {
        assertTrue(policy.canPublish(as("svc-ids", "servicio"), "ids"));
        assertTrue(policy.canPublish(as("svc-honeypot", "servicio"), "honeypot"));
        assertTrue(policy.canPublish(as("svc-escaner", "servicio"), "scanner"));
        assertTrue(policy.canPublish(as("svc-pentesting", "servicio"), "pentesting"));
        assertFalse(policy.canPublish(as("svc-ids", "servicio"), "honeypot"));
        assertFalse(policy.canPublish(as("svc-escaner", "servicio"), "ids"));
        assertFalse(policy.canPublish(as("svc-soar", "servicio"), "ids"));
        assertFalse(policy.canPublish(as("root", "admin"), "ids"));
        assertFalse(policy.canPublish(null, "ids"));
        assertFalse(policy.canPublish(as("svc-ids", "servicio"), null));
    }

    @Test
    void onlyHumansReadTheEventHistory() {
        assertTrue(policy.canAccess(as("ana", "analista"), "GET", "/events"));
        assertTrue(policy.canAccess(as("root", "admin"), "GET", "/events"));
        assertFalse(policy.canAccess(as("svc-soar", "servicio"), "GET", "/events"));
        assertFalse(policy.canAccess(as("svc-ids", "servicio"), "GET", "/events"));
    }

    @Test
    void alertsAreReadBySoarAndHumans() {
        for (String path : new String[] {"/alerts", "/alerts/ALERT-1"}) {
            assertTrue(policy.canAccess(as("svc-soar", "servicio"), "GET", path), path);
            assertTrue(policy.canAccess(as("ana", "analista"), "GET", path), path);
            assertTrue(policy.canAccess(as("root", "admin"), "GET", path), path);
            assertFalse(policy.canAccess(as("svc-honeypot", "servicio"), "GET", path), path);
            assertFalse(policy.canAccess(as("svc-siem", "servicio"), "GET", path), path);
        }
        // svc-soar solo cuenta como SOAR si G1 le da el rol servicio.
        assertFalse(policy.canAccess(as("svc-soar", "analista2"), "GET", "/alerts"));
    }

    @Test
    void anythingOutsideTheMatrixIsDenied() {
        assertFalse(policy.canAccess(as("ana", "desconocido"), "GET", "/alerts"));
        assertFalse(policy.canAccess(as("root", "admin"), "DELETE", "/alerts/ALERT-1"));
        assertFalse(policy.canAccess(as("root", "admin"), "GET", "/alerts/a/b"));
        assertFalse(policy.canAccess(as("root", "admin"), "GET", "/otra-ruta"));
        assertFalse(policy.canAccess(null, "GET", "/alerts"));
    }
}