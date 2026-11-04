// Cliente de Identidad. Todas las llamadas pasan por el proxy nginx (/api/identidad/), ver default.conf.
const AUTH_BASE = "/api/identidad";
const TOKEN_KEY = "token"; // misma clave que lee SIEM-client.js; sessionStorage, nunca localStorage

export function getToken() {
    return sessionStorage.getItem(TOKEN_KEY);
}

// Devuelve { ok: true, user } o { ok: false, reason, retryAfter? }
// reason: "invalid_credentials" (401) | "rate_limited" (429) | "bad_request" (400) | "server" (5xx/502/red)
export async function login(username, password) {
    let res;
    try {
        res = await fetch(`${AUTH_BASE}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });
    } catch {
        return { ok: false, reason: "server" };
    }
    if (res.status === 200) {
        const { token, user } = await res.json();
        sessionStorage.setItem(TOKEN_KEY, token);
        return { ok: true, user };
    }
    if (res.status === 429) {
        const retryAfter = parseInt(res.headers.get("Retry-After"), 10);
        return { ok: false, reason: "rate_limited", retryAfter: Number.isNaN(retryAfter) ? null : retryAfter };
    }
    if (res.status === 400) return { ok: false, reason: "bad_request" };
    if (res.status === 401) return { ok: false, reason: "invalid_credentials" };
    return { ok: false, reason: "server" };
}

// Para la 83 (validar al abrir el Dashboard). Devuelve { valid: true, user_id, username, role } o { valid: false, status?, reason? }
export async function validate() {
    const token = getToken();
    if (!token) return { valid: false, reason: "no_token" };
    try {
        const res = await fetch(`${AUTH_BASE}/auth/validate`, {
            headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) return { valid: true, ...(await res.json()) };
        return { valid: false, status: res.status };
    } catch {
        return { valid: false, reason: "server" };
    }
}

// Para la 84 (Jaime). Descarta el token siempre y avisa a Identidad para que lo revoque.
export async function logout() {
    const token = getToken();
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem("logged_in");
    if (!token) return;
    try {
        await fetch(`${AUTH_BASE}/auth/logout`, {
            method: "POST",
            headers: { Authorization: `Bearer ${token}` },
        });
    } catch { /* el token ya está descartado en el navegador */ }

}

// 83: guarda de sesión al abrir una página protegida.
// Sin token, con token rechazado por /auth/validate o con Identidad caída, se redirige al login (falla cerrado).
export async function requireSession() {
    const result = await validate();
    if (result.valid) {
        document.getElementById("guard-style")?.remove(); // muestra la página
        return result;
    }
    if (result.status === 401) sessionStorage.removeItem(TOKEN_KEY); // token caducado, revocado o manipulado
    window.location.replace("login.html"); // replace: el botón Atrás no vuelve a la página protegida
    return null;
}