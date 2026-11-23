import unittest
from xml.etree.ElementTree import ParseError

from parser import parse_xml, severity_from_cvss


def nmap_xml(script_xml="", hostscript_xml=""):
    return f'''<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up" />
        <address addr="192.0.2.10" addrtype="ipv4" />
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open" />
            <service name="https" />
            {script_xml}
          </port>
        </ports>
        {hostscript_xml}
      </host>
    </nmaprun>'''


class TestParser(unittest.TestCase):
    def test_normaliza_puerto_servicio_y_cve(self):
        output_text = "VULNERABLE: CVE-2024-12345 CVSS:3.1:9.8"
        xml = nmap_xml(
            f'<script id="vuln-demo" output="{output_text}" />'
        )
        events = parse_xml(xml, "scan-1", "vuln")
        by_type = {event["event_type"]: event for event in events}

        self.assertEqual(set(by_type), {"port_open", "service_detected", "cve_detected"})
        self.assertEqual(by_type["port_open"]["severity"], "info")
        self.assertEqual(by_type["service_detected"]["severity"], "info")
        self.assertIsNone(by_type["port_open"]["details"]["evidence"])
        self.assertIsNone(by_type["service_detected"]["details"]["evidence"])

        finding = by_type["cve_detected"]
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["source"], "scanner")
        self.assertEqual(finding["details"]["cve"], "CVE-2024-12345")
        self.assertEqual(finding["details"]["scan_id"], "scan-1")
        self.assertEqual(finding["details"]["profile"], "vuln")
        self.assertEqual(finding["details"]["target"], {
            "ip": "192.0.2.10", "port": 443, "protocol": "tcp", "service": "https",
        })
        self.assertIsNotNone(finding["details"]["evidence"])
        self.assertLessEqual(len(finding["details"]["evidence"]), 300)
        self.assertTrue(finding["timestamp"].endswith("Z"))

    def test_evidencia_larga_se_recorta_sin_exceder_limite(self):
        long_output = "VULNERABLE: " + ("A" * 500)
        xml = nmap_xml(f'<script id="vuln-long" output="{long_output}" />')
        events = parse_xml(xml, "scan-long", "vuln")
        findings = [e for e in events if e["event_type"] == "vulnerability_detected"]

        self.assertEqual(len(findings), 1)
        evidence = findings[0]["details"]["evidence"]
        self.assertIsNotNone(evidence)
        self.assertLessEqual(len(evidence), 300)
        self.assertTrue(evidence.endswith("..."))

    def test_not_vulnerable_no_crea_falso_positivo_por_cve_en_evidencia(self):
        xml = nmap_xml(
            '<script id="vuln-demo" output="NOT VULNERABLE\\nReference: CVE-2024-12345" />'
        )
        events = parse_xml(xml, "scan-2")
        self.assertFalse(any(event["event_type"] in ("cve_detected", "vulnerability_detected") for event in events))

    def test_hallazgo_nse_a_nivel_de_host_sin_puerto(self):
        xml = nmap_xml(hostscript_xml=(
            '<hostscript><script id="host-vuln" output="VULNERABLE: host setting" />'
            '</hostscript>'
        ))
        findings = [event for event in parse_xml(xml, "scan-3")
                    if event["event_type"] == "vulnerability_detected"]
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]["details"]["target"]["port"])
        self.assertEqual(findings[0]["details"]["script_id"], "host-vuln")
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIsNotNone(findings[0]["details"]["evidence"])

    def test_errores_y_salidas_vacias_se_ignoran(self):
        xml = nmap_xml(
            '<script id="empty" output="" />'
            '<script id="error" output="ERROR: script failed; VULNERABLE" />'
        )
        self.assertFalse(any(event["event_type"] in ("cve_detected", "vulnerability_detected")
                             for event in parse_xml(xml, "scan-4")))

    def test_cvss_y_xml_invalido(self):
        self.assertEqual([severity_from_cvss(score) for score in (None, 3.9, 4.0, 7.0, 9.0)],
                         ["medium", "low", "medium", "high", "critical"])
        with self.assertRaises(ParseError):
            parse_xml("<nmaprun>", "scan-invalid")


if __name__ == "__main__":
    unittest.main(verbosity=2)