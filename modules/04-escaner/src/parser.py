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

def clean_evidence(text, max_len=300):
    if not text:
        return None
    compact = " ".join(str(text).split())
    if not compact:
        return None
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3].rstrip() + "..."

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
    cve=None,
    cvss=None,
    evidence=None,
    # El contrato del SIEM ya admite "info"; los eventos informativos
    # usan su nivel permitido más bajo y el Dashboard los filtra del informe.
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
        "details": { #hay que incluir evidence (evidencia textual o null si no aplica)
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


CVE_LINE_SCORE_RE = re.compile(
    r"\b(CVE-\d{4}-\d{4,7})\b[ \t]+(\d{1,2}\.\d)\b",
    re.IGNORECASE
)


def _to_score(value):
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0 <= score <= 10 else None


def _cvss_by_cve(script):
    """Devuelve {CVE: cvss}, leyendo primero las tablas del XML."""
    scores = {}

    def add(cve, score):
        if score is None:
            return
        cve = cve.upper()
        scores[cve] = max(score, scores.get(cve, 0.0))

    # 1) XML estructurado
    for table in script.iter("table"):
        elems = {
            e.get("key"): (e.text or "").strip()
            for e in table.findall("elem")
            if e.get("key")
        }

        # vulners: <elem key="id">CVE-...</elem> + <elem key="cvss">7.5</elem>
        if CVE_RE.fullmatch(elems.get("id", "")):
            add(elems["id"], _to_score(elems.get("cvss")))
            continue

        # smb-vuln-*, http-vuln-*: tabla "scores" dentro de cada vulnerabilidad
        table_scores = [
            _to_score(e.text)
            for e in table.findall("table[@key='scores']/elem")
        ]
        best = max((s for s in table_scores if s is not None), default=None)
        if best is not None:
            ids = [e.text or "" for e in table.findall("table[@key='ids']/elem")]
            ids.append(table.get("key") or "")
            for text in ids:
                for cve in CVE_RE.findall(text):
                    add(cve, best)

    # 2) Respaldo: texto "CVE-XXXX-YYYY   7.5   url"
    output = script.get("output") or ""
    for cve, s in CVE_LINE_SCORE_RE.findall(output):
        if cve.upper() not in scores:
            add(cve, _to_score(s))

    return scores


def _parse_script(script, ip, scan_id, profile, port=None, protocol=None, service=None):
    """Convierte un resultado NSE positivo en eventos del contrato común."""
    script_id = script.get("id") or "script-desconocido"
    output = (script.get("output") or "").strip()
    if not output or "ERROR:" in output.upper() or not is_vulnerable(output):
        return []

    cves = list(dict.fromkeys(cve.upper() for cve in CVE_RE.findall(output)))
    scores = _cvss_by_cve(script)

    # Respaldo: "CVSS: 9.8" cuando hay un único CVE sin score
    if len(cves) == 1 and cves[0] not in scores:
        m = CVSS_RE.search(output)
        if m and _to_score(m.group(1)) is not None:
            scores[cves[0]] = _to_score(m.group(1))

    events = []
    for cve in cves:
        cvss = scores.get(cve)
        events.append(make_event(
            event_type="cve_detected",
            title=f"CVE detectado: {cve}",
            description=f"El script {script_id} ha identificado una referencia a {cve}.",
            ip=ip, port=port, protocol=protocol, service=service,
            script_id=script_id, cve=cve, cvss=cvss,
            evidence=clean_evidence(output),
            scan_id=scan_id, profile=profile,
            severity=severity_from_cvss(cvss),
        ))

    if not cves:
        events.append(make_event(
            event_type="vulnerability_detected",
            title=f"Posible vulnerabilidad: {script_id}",
            description=f"El script {script_id} ha señalado un posible problema de seguridad.",
            ip=ip, port=port, protocol=protocol, service=service,
            script_id=script_id, scan_id=scan_id,
            evidence=clean_evidence(output),
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
