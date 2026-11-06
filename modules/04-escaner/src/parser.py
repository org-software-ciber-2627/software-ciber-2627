import re
import uuid
import xml.etree.ElementTree as ET

from datetime import datetime, timezone


CVE_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE
)

CVSS_RE = re.compile(
    r"\bCVSS(?::\s*v?\d(?:\.\d)?)?\s*[:=]?\s*"
    r"(\d{1,2}\.\d)\b",
    re.IGNORECASE
)


def now_iso():
    return datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def severity_from_cvss(cvss):
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def make_event(
    event_type,
    title,
    description,
    ip,
    scan_id,
    profile,
    port=None,
    protocol=None,
    service=None,
    script_id=None,
    evidence=None,
    cve=None,
    cvss=None,
    # El contrato del SIEM no admite "info"; los eventos informativos
    # usan su nivel permitido más bajo y el Dashboard los filtra del informe.
    severity="low"
):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": now_iso(),
        "source": "scanner",
        "event_type": event_type,
        "severity": severity,
        "title": title,
        "description": description,
        "details": {
            "target": {
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "service": service
            },
            "scan_id": scan_id,
            "tool": "nmap",
            "profile": profile,
            "script_id": script_id,
            "evidence": evidence,
            "cve": cve,
            "cvss": cvss
        }
    }


def is_vulnerable(output):
    # Nmap puede incluir CVE en texto explicativo aunque indique
    # explícitamente que el objetivo NO es vulnerable.
    if re.search(r"\bNOT\s+VULNERABLE\b", output, flags=re.IGNORECASE):
        return False
    return bool(re.search(r"\bVULNERABLE\b", output, flags=re.IGNORECASE) or CVE_RE.search(output))


def _parse_script(script, ip, scan_id, profile, port=None, protocol=None, service=None):
    """Convierte un resultado NSE positivo en eventos del contrato común."""
    script_id = script.get("id") or "script-desconocido"
    output = (script.get("output") or "").strip()
    if not output or "ERROR:" in output.upper() or not is_vulnerable(output):
        return []

    cves = list(dict.fromkeys(cve.upper() for cve in CVE_RE.findall(output)))
    scores = [float(score) for score in CVSS_RE.findall(output) if 0 <= float(score) <= 10.0]
    events = []
    for index, cve in enumerate(cves):
        cvss = scores[index] if index < len(scores) else None
        events.append(make_event(
            event_type="cve_detected",
            title=f"CVE detectado: {cve}",
            description=f"El script {script_id} ha identificado una referencia a {cve}.",
            ip=ip, port=port, protocol=protocol, service=service,
            script_id=script_id, evidence=output, cve=cve, cvss=cvss,
            scan_id=scan_id, profile=profile,
            severity=severity_from_cvss(cvss),
        ))

    if not cves:
        events.append(make_event(
            event_type="vulnerability_detected",
            title=f"Posible vulnerabilidad: {script_id}",
            description=f"El script {script_id} ha señalado un posible problema de seguridad.",
            ip=ip, port=port, protocol=protocol, service=service,
            script_id=script_id, evidence=output, scan_id=scan_id,
            profile=profile, severity="medium",
        ))
    return events


def parse_xml(xml_text, scan_id, profile="vuln"):
    events = []
    root = ET.fromstring(xml_text)

    for host in root.findall("host"):
        # Obtener la dirección IP.
        ip = next(
            (
                addr.get("addr")
                for addr in host.findall("address")
                if addr.get("addrtype") in ("ipv4", "ipv6")
            ),
            None
        )

        if not ip:
            continue

        for port_node in host.findall("ports/port"):
            state_node = port_node.find("state")

            if state_node is None:
                continue

            state = state_node.get("state")
            port = int(port_node.get("portid"))
            protocol = port_node.get("protocol")

            service_node = port_node.find("service")
            service = (
                service_node.get("name")
                if service_node is not None
                else None
            )

            # Evento: puerto abierto.
            if state == "open":
                events.append(make_event(
                    event_type="port_open",
                    title=f"Puerto abierto: {port}",
                    description=f"Puerto {port}/{protocol} abierto.",
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    service=service,
                    scan_id=scan_id,
                    profile=profile
                ))

            # Evento: servicio detectado.
            if state == "open" and service:
                events.append(make_event(
                    event_type="service_detected",
                    title=f"Servicio detectado: {service}",
                    description=(
                        f"Servicio {service} detectado "
                        f"en el puerto {port}."
                    ),
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    service=service,
                    scan_id=scan_id,
                    profile=profile
                ))

            for script in port_node.findall("script"):
                events.extend(_parse_script(
                    script, ip, scan_id, profile, port=port,
                    protocol=protocol, service=service,
                ))

        # Algunos NSE se ejecutan a nivel de host y no tienen puerto.
        for script in host.findall("hostscript/script"):
            events.extend(_parse_script(script, ip, scan_id, profile))

    return events
