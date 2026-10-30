import subprocess

PROFILES = {
    "vuln":  ["-sT", "-sV", "--script", "vuln"],
    "web":   ["-sT", "-sV", "-p", "80,443,8080,8443", "--script", "http-*"],
    "quick": ["-sT"],
}

#este archivo gestiona la ejecucion de nmap 


def get_profiles():
    return list(PROFILES.keys())


def start_nmap(target, profile, outfile):
    """Lanza nmap en segundo plano; el XML se escribe en outfile."""
    if target.startswith("-"):
        raise ValueError("Objetivo no válido")
    cmd = ["nmap", *PROFILES[profile], "-oX", outfile, target]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
