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
    severity="info"
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
    # Evitar falsos positivos por resultados negativos.
    cleaned = re.sub(
        r"\bNOT\s+VULNERABLE\b",
        "",
        output,
        flags=re.IGNORECASE
    )

    cleaned = re.sub(
        r"\bNOT\s+VULNERABLE\s*:\s*",
        "",
        cleaned,
        flags=re.IGNORECASE
    )

    return (
        "VULNERABLE" in cleaned.upper()
        or bool(CVE_RE.search(output))
    )


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

            # Analizar los scripts NSE asociados al puerto.
            for script in port_node.findall("script"):
                script_id = script.get("id")
                output = script.get("output", "").strip()

                if not output:
                    continue

                # Evento: error de ejecución de NSE.
                # Ignorar errores y salidas vacías de scripts NSE.
                if not output or "ERROR:" in output.upper():
                    continue

                if not is_vulnerable(output):
                    continue

                # Extraer las referencias CVE.
                cves = list(dict.fromkeys(
                    cve.upper()
                    for cve in CVE_RE.findall(output)
                ))

                # Extraer puntuaciones CVSS disponibles.
                scores = [
                    float(score)
                    for score in CVSS_RE.findall(output)
                    if float(score) <= 10.0
                ]

                if cves:
                    # Un evento por cada CVE encontrado.
                    for index, cve in enumerate(cves):
                        cvss = scores[index] if index < len(scores) else None

                        events.append(make_event(
                            event_type="cve_detected",
                            title=f"CVE detectado: {cve}",
                            description=(
                                f"El script {script_id} "
                                f"ha identificado una referencia a {cve}."
                            ),
                            ip=ip,
                            port=port,
                            protocol=protocol,
                            service=service,
                            script_id=script_id,
                            evidence=output,
                            cve=cve,
                            cvss=cvss,
                            scan_id=scan_id,
                            profile=profile,
                            severity=severity_from_cvss(cvss)
                        ))

                else:
                    # El script indica una posible vulnerabilidad
                    # pero no proporciona una referencia CVE.
                    events.append(make_event(
                        event_type="vulnerability_detected",
                        title=f"Posible vulnerabilidad: {script_id}",
                        description=(
                            f"El script {script_id} ha señalado "
                            "un posible problema de seguridad."
                        ),
                        ip=ip,
                        port=port,
                        protocol=protocol,
                        service=service,
                        script_id=script_id,
                        evidence=output,
                        scan_id=scan_id,
                        profile=profile,
                        severity="medium"
                    ))

    return events
