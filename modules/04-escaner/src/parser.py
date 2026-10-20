import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

CVE_SCORE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}\.\d)", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# el parser sirve para procesar el XML que genera nmap y tranformarla en eventos de seguridad estructurados
def severity_from_cvss(cvss):
    if cvss is None:
        return "medium"  # sin puntuación: valor por defecto
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_vulnerable(output):
    """Filtro simple: solo nos interesan scripts que reporten algo."""
    return "VULNERABLE" in output.upper() or bool(CVE_RE.search(output))


def build_event(ip, port, protocol, service, script_id, output, scan_id, profile, cve, cvss):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": now_iso(),
        "source": "scanner",
        "event_type": "vulnerability_detected",
        "severity": severity_from_cvss(cvss),
        "title": cve or script_id,
        "description": output.strip().splitlines()[0] if output.strip() else script_id,
        "details": {
            "target": {
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "service": service,
            },
            "scan_id": scan_id,
            "tool": "nmap",
            "profile": profile,
            "script_id": script_id,
            "evidence": output.strip(),
            "cve": cve,
            "cvss": cvss,
        },
    }


def parse_xml(xml_text, scan_id, profile="vuln"):
    """Devuelve una lista de eventos (dicts) listos para enviar al SIEM."""
    events = []
    root = ET.fromstring(xml_text)

    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else None

        for p in host.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue

            svc = p.find("service")
            port = int(p.get("portid"))
            protocol = p.get("protocol")
            service = svc.get("name") if svc is not None else None

            for s in p.findall("script"):
                script_id = s.get("id", "")
                output = s.get("output", "")
                if not is_vulnerable(output):
                    continue

                pairs = CVE_SCORE_RE.findall(output)
                if pairs:
                    # un evento por cada CVE
                    for cve, score in pairs:
                        events.append(build_event(ip, port, protocol, service, script_id,
                                                  output, scan_id, profile,
                                                  cve.upper(), float(score)))
                else:
                    events.append(build_event(ip, port, protocol, service, script_id,
                                              output, scan_id, profile, None, None))
    return events
