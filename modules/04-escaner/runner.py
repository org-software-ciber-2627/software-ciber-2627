import subprocess

PROFILES = {
    "vuln": ["-sT", "-sV", "--script", "vuln"],
    "web": ["-sT", "-sV", "-p", "80,443,8080,8443", "--script", "http-*"],
    "quick": ["-sT"],
}


def get_profiles():
    return list(PROFILES.keys())


def start_nmap(target, profile, outfile):
    if target.startswith("-"):
        raise ValueError("Objetivo no válido")
    command = ["nmap", *PROFILES[profile], "-oX", outfile, target]
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
