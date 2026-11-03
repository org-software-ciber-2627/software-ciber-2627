import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

CVE_SCORE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}\.\d)", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


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


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_vulnerable(output):
    return "VULNERABLE" in output.upper() or bool(CVE_RE.search(output))


def build_event(ip, port, protocol, service, script_id, output, scan_id, profile, cve, cvss):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": now_iso(),
        "source": "vulnerability_scanner",
        "event_type": "vulnerability_detected",
        "severity": severity_from_cvss(cvss),
        "title": cve or script_id,
        "description": output.strip().splitlines()[0] if output.strip() else script_id,
        "target": {
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "service": service,
        },
        "details": {
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
    events = []
    root = ET.fromstring(xml_text)

    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr") if address is not None else None

        for port_info in host.findall("ports/port"):
            state = port_info.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port_info.find("service")
            port = int(port_info.get("portid"))
            protocol = port_info.get("protocol")
            service_name = service.get("name") if service is not None else None

            for script in port_info.findall("script"):
                script_id = script.get("id", "")
                output = script.get("output", "")
                if not is_vulnerable(output):
                    continue

                pairs = CVE_SCORE_RE.findall(output)
                if pairs:
                    for cve, score in pairs:
                        events.append(
                            build_event(
                                ip, port, protocol, service_name, script_id, output, scan_id, profile, cve.upper(), float(score)
                            )
                        )
                else:
                    events.append(build_event(ip, port, protocol, service_name, script_id, output, scan_id, profile, None, None))

    return events
