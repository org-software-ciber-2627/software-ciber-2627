import os
import subprocess

# Este archivo gestiona la ejecución de nmap.

NMAP_TIMEOUT_SECONDS = int(os.environ.get("NMAP_TIMEOUT_SECONDS", "1200"))
VULN_SCRIPT_TIMEOUT = os.environ.get("NMAP_VULN_SCRIPT_TIMEOUT", "60s")
VULN_HOST_TIMEOUT = os.environ.get("NMAP_VULN_HOST_TIMEOUT", "15m")


WEB_SCRIPTS = [
    # Vulnerabilidades conocidas (CVE)
    "http-vuln-cve2017-5638",       # Apache Struts RCE
    "http-vuln-cve2015-1635",       # MS15-034 HTTP.sys
    "http-vuln-cve2011-3192",       # Apache byterange
    "http-slowloris-check",         # solo comprueba, no lanza el ataque
    "http-shellshock",
    # Configuración insegura (OWASP A05 / A01)
    "http-security-headers",
    "http-cookie-flags",
    "http-methods",
    "http-trace",
    "http-cors",
    "http-internal-ip-disclosure",
    "http-git",
    "http-enum",
    # Inventario
    "http-title",
    "http-server-header",
]


WEB_PORTS = "80,443,8080,8443,8000-8010"


WEB_SCRIPT_TIMEOUT = "60s"   # máximo por script
WEB_HOST_TIMEOUT = "10m"     # máximo por host

PROFILES = {
    "vuln":  ["-sT", "-sV", "--script", "vuln",
              "--script-timeout", VULN_SCRIPT_TIMEOUT,
              "--host-timeout", VULN_HOST_TIMEOUT],
    "web":   ["-sT", "-sV",
              "-p", WEB_PORTS,
              "--script", ",".join(WEB_SCRIPTS),
              "--script-timeout", WEB_SCRIPT_TIMEOUT,
              "--host-timeout", WEB_HOST_TIMEOUT],
    "quick": ["-sT"],
}


def get_profiles():
    return list(PROFILES.keys())


def build_command(target, profile, outfile):
    """Construye el comando de nmap sin ejecutarlo (facilita los tests)."""
    if not isinstance(target, str) or not target.strip() or target.strip().startswith("-"):
        raise ValueError("Objetivo no válido")
    if profile not in PROFILES:
        raise ValueError(f"Perfil no válido: {profile}")
    return ["nmap", *PROFILES[profile], "-oX", outfile, target.strip()]


def start_nmap(target, profile, outfile):
    """Lanza nmap en segundo plano; el XML se escribe en outfile."""
    cmd = build_command(target, profile, outfile)
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
