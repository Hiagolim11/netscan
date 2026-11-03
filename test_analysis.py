"""Testes da análise automática: python3 -m unittest test_analysis"""
import json
import os
import tempfile
import time
import unittest

import analysis


def fake_intel(kev=("CVE-2017-0144",), epss=None):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "kev.json"), "w") as f:
        json.dump({"vulnerabilities": [{"cveID": c, "knownRansomwareCampaignUse": "Known"} for c in kev]}, f)
    with open(os.path.join(d, "epss.json"), "w") as f:
        json.dump({c: [s, time.time()] for c, s in (epss or {}).items()}, f)
    return analysis.Intel(offline=True, cache_dir=d)


class TestAnalysis(unittest.TestCase):
    def test_intel_enrich_offline(self):
        intel = fake_intel(epss={"CVE-2017-0144": 0.97, "CVE-2000-0001": 0.01})
        vulns = [{"cves": ["CVE-2017-0144", "CVE-2000-0001"]}, {"cves": ["CVE-2999-9999"]}]
        intel.enrich(vulns)
        self.assertEqual(vulns[0]["kev"], ["CVE-2017-0144"])
        self.assertTrue(vulns[0]["ransomware"])
        self.assertEqual(vulns[0]["epss"], 0.97)
        self.assertEqual(vulns[1]["kev"], [])
        self.assertIsNone(vulns[1]["epss"])  # offline e sem cache: sem EPSS, sem erro

    def test_confidence(self):
        c = analysis.confidence
        self.assertEqual(c({"title": "FTP anônimo"}), "high")
        self.assertEqual(c({"output": "State: VULNERABLE\n"}), "high")
        self.assertEqual(c({"output": "State: LIKELY VULNERABLE"}), "medium")
        self.assertEqual(c({"id": "vulners", "output": "CVE-1"}), "medium")

    def test_score_kev_beats_higher_cvss(self):
        exploited = {"cvss": 7.5, "kev": ["CVE-X"], "epss": 0.9, "confidence": "high"}
        theoretical = {"cvss": 9.8, "kev": [], "epss": 0.001, "confidence": "medium"}
        s1, r1 = analysis.score_vuln(exploited)
        s2, _ = analysis.score_vuln(theoretical)
        self.assertGreater(s1, s2)
        self.assertTrue(any("KEV" in r for r in r1))
        self.assertLessEqual(analysis.score_vuln({"cvss": 10, "kev": ["x"], "epss": 1, "confidence": "high"}, True)[0], 100)

    def test_device_type(self):
        dt = analysis.device_type
        self.assertEqual(dt({"ip": "10.0.0.1", "ports": []}, gateway="10.0.0.1"), "router")
        self.assertEqual(dt({"ip": "a", "ports": [{"port": "9100"}]}), "printer")
        self.assertEqual(dt({"ip": "a", "ports": [{"port": "554", "service": "rtsp"}]}), "camera")
        self.assertEqual(dt({"ip": "a", "ports": [{"port": "445"}]}), "windows")
        self.assertEqual(dt({"ip": "a", "ports": [], "mac": "72:20:B4:B6:69:AB"}), "phone")  # MAC aleatório
        self.assertEqual(dt({"ip": "a", "ports": [], "vendor": "Apple"}), "phone")
        self.assertEqual(dt({"ip": "a", "ports": [{"port": "22"}], "mac": "00:11:22:33:44:55"}), "linux")
        self.assertEqual(dt({"ip": "a", "ports": [], "mac": "00:11:22:33:44:55"}), "unknown")

    def test_camera_telnet_escalates(self):
        h = {"ip": "a", "ports": [{"port": "554", "service": "rtsp"}, {"port": "23", "service": "telnet"}],
             "vulns": [{"port": "23", "id": "insecure-service", "title": "Telnet", "severity": "medium", "cves": []}]}
        analysis.analyze_host(h)
        self.assertEqual(h["type"], "camera")
        self.assertEqual(h["vulns"][0]["severity"], "high")
        self.assertTrue(h["vulns"][0]["notes"])
        self.assertEqual(h["severity"]["high"], 1)
        self.assertGreater(h["risk"], 0)

    def test_analyze_network(self):
        intel = fake_intel()
        hosts = [
            {"ip": "10.0.0.5", "ports": [{"port": "445"}], "vulns": [
                {"port": "445", "id": "smb-vuln-ms17-010", "output": "State: VULNERABLE", "cves": ["CVE-2017-0144"],
                 "cvss": 8.1, "severity": "high", "fix": "patch"}]},
            {"ip": "10.0.0.9", "ports": [], "vulns": [], "mac": "00:11:22:33:44:55"},
        ]
        for h in hosts:
            analysis.analyze_host(h, intel)
        an = analysis.analyze_network(hosts, {"new_hosts": ["10.0.0.9"]})
        self.assertEqual(an["top"][0]["ip"], "10.0.0.5")
        self.assertEqual(analysis.finding_title(
            {"ports": [{"port": "80", "product": "lighttpd", "version": "1.4.35"}]},
            {"id": "vulners", "port": "80", "cves": ["a", "b"]}), "Versão vulnerável de lighttpd 1.4.35 (2 CVEs)")
        self.assertIn("explorada ativamente (CISA KEV) · usada por ransomware", an["top"][0]["reasons"])
        self.assertEqual(an["level"], "critical")
        text = " ".join(an["summary"])
        self.assertIn("CVE-2017-0144", text)
        self.assertIn("10.0.0.9", text)  # dispositivo novo citado no resumo

    def test_clean_network(self):
        an = analysis.analyze_network([analysis.analyze_host({"ip": "a", "ports": [], "vulns": []})])
        self.assertEqual((an["risk"], an["level"]), (0, "none"))
        self.assertIn("Nenhum problema relevante", " ".join(an["summary"]))


if __name__ == "__main__":
    unittest.main()
