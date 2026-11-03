"""Testes rápidos da lógica pura do netscan: python3 -m unittest test_netscan"""
import os
import tempfile
import unittest

import netscan


class TestNetscan(unittest.TestCase):
    def test_split_targets(self):
        self.assertEqual(netscan.split_targets("10.0.0.0/24, 192.168.1.5  host"),
                         ["10.0.0.0/24", "192.168.1.5", "host"])
        self.assertEqual(netscan.split_targets(""), [])

    def test_ports_re(self):
        for ok in ["22", "22,80,443", "1-1024", "T:80,U:53"]:
            self.assertTrue(netscan.PORTS_RE.match(ok), ok)
        for bad in ["22;rm", "--script x", "80 443"]:
            self.assertFalse(netscan.PORTS_RE.match(bad), bad)

    def test_diff_reports(self):
        old = [
            {"ip": "10.0.0.1", "ports": [{"port": "22", "proto": "tcp"}],
             "vulns": [{"port": "22", "id": "ssh-old"}]},
            {"ip": "10.0.0.2", "ports": [], "vulns": []},
        ]
        new = [
            {"ip": "10.0.0.1", "ports": [{"port": "22", "proto": "tcp"}, {"port": "80", "proto": "tcp"}],
             "vulns": []},
            {"ip": "10.0.0.3", "ports": [], "vulns": []},
        ]
        d = netscan.diff_reports(old, new)
        self.assertEqual(d["new_hosts"], ["10.0.0.3"])
        self.assertEqual(d["gone_hosts"], ["10.0.0.2"])
        self.assertEqual(d["changed"]["10.0.0.1"], {
            "new_ports": ["80/tcp"], "closed_ports": [],
            "new_vulns": [], "fixed_vulns": ["22:ssh-old"]})

    def test_severity(self):
        self.assertEqual(netscan.classify_severity(9.8), "critical")
        self.assertEqual(netscan.classify_severity(5.0), "medium")
        self.assertEqual(netscan.classify_severity(None, "VULNERABLE"), "medium")

    def test_exploit_query(self):
        self.assertEqual(netscan.exploit_query("OpenSSH", "7.4p1 Debian 10+deb9u7"), "OpenSSH 7.4")
        self.assertIsNone(netscan.exploit_query("nginx", None))
        self.assertIsNone(netscan.exploit_query("x", "unknown"))

    def test_stats_re(self):
        m = netscan.STATS_RE.search("SYN Stealth Scan Timing: About 12.67% done; ETC: 01:16 (0:00:13 remaining)")
        self.assertEqual((m.group(1), m.group(2), m.group(3)), ("SYN Stealth Scan", "12.67", "0:00:13"))

    def test_parse_host_scan(self):
        xml = """<nmaprun><host><status state="up"/>
          <os><osmatch name="Linux 5.X" accuracy="95"/></os>
          <ports>
            <port protocol="tcp" portid="22"><state state="open"/>
              <service name="ssh" product="OpenSSH" version="7.4"/>
              <script id="vulners" output="cpe:/a:openbsd:openssh:7.4&#10;  CVE-2023-38408  9.8  https://x&#10;  CVE-2016-10009  7.5  https://y"/>
            </port>
            <port protocol="tcp" portid="80"><state state="open"/>
              <service name="http" tunnel="ssl"/>
              <script id="http-csrf" output="Couldn't find any CSRF vulnerabilities."/>
            </port>
            <port protocol="tcp" portid="25"><state state="closed"/></port>
            <port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
          </ports></host></nmaprun>"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(xml)
        try:
            r = netscan.parse_host_scan(f.name, "10.0.0.1")
        finally:
            os.unlink(f.name)
        self.assertEqual([p["port"] for p in r["ports"]], ["22", "80", "23"])
        self.assertEqual(r["ports"][1]["tunnel"], "ssl")
        self.assertEqual(r["os"]["name"], "Linux 5.X")
        self.assertEqual(len(r["vulns"]), 2)  # vulners + telnet; o "Couldn't find" é filtrado
        self.assertEqual(r["vulns"][1]["id"], "insecure-service")
        v = r["vulns"][0]
        self.assertIn("OpenSSH 7.4", v["fix"])
        self.assertEqual((v["severity"], v["cvss"]), ("critical", 9.8))
        self.assertEqual(v["cves"], ["CVE-2023-38408", "CVE-2016-10009"])
        self.assertEqual(r["severity"]["critical"], 1)

    def test_config_finding(self):
        cf = netscan.config_finding
        self.assertEqual(cf("ftp-anon", "Anonymous FTP login allowed (FTP code 230)")[0], "medium")
        self.assertEqual(cf("ssl-enum-ciphers", "least strength: F")[0], "high")
        self.assertIsNone(cf("ssl-enum-ciphers", "least strength: A"))
        self.assertEqual(cf("ssl-cert", "Not valid after:  2001-01-01T00:00:00")[0], "low")
        self.assertIsNone(cf("ssl-cert", "Not valid after:  2999-01-01T00:00:00"))
        self.assertIsNone(cf("smb2-security-mode", "Message signing enabled and required"))

    def test_remediation(self):
        r = netscan.remediation
        self.assertIn("MS17-010", r({"id": "smb-vuln-ms17-010"}))
        self.assertIn("SMBv1", r({"id": "smb-vuln-ms08-067"}))  # prefixo
        self.assertIn("OpenSSH 7.4", r({"id": "vulners", "cves": ["CVE-1"]}, "OpenSSH 7.4"))
        self.assertTrue(r({"id": "algo-desconhecido"}))

    def test_merge_ipv6(self):
        hosts = [{"ip": "192.168.0.1", "mac": "02:10:18:AE:49:14"}]
        found = [{"ip": "2804::1", "mac": "02:10:18:ae:49:14"},
                 {"ip": "fe80::5", "mac": "AA:BB:CC:DD:EE:FF"},
                 {"ip": "2804::1", "mac": "02:10:18:AE:49:14"}]
        netscan.merge_ipv6(hosts, found, "wlan0")
        self.assertEqual(hosts[0]["ipv6"], ["2804::1"])  # mesmo aparelho, sem duplicar
        self.assertEqual(hosts[1]["ip"], "fe80::5%wlan0")  # só IPv6: vira host, com interface
        self.assertEqual(len(hosts), 2)

    def test_select_scripts(self):
        sel = netscan.select_scripts
        web = sel([{"port": "8081", "proto": "tcp", "service": "http"}])
        self.assertIn("http-title", web)          # casa pelo nome do serviço, não só pela porta
        self.assertNotIn("smb-protocols", web)    # não roda o que não se aplica
        self.assertNotIn("http-default-accounts", web)  # senha padrão só com opt-in
        self.assertIn("http-default-accounts", sel([{"port": "80", "proto": "tcp", "service": "http"}], default_creds=True))
        tls = sel([{"port": "9443", "proto": "tcp", "service": "http", "tunnel": "ssl"}])
        self.assertIn("ssl-enum-ciphers", tls)
        smb = sel([{"port": "445", "proto": "tcp", "service": "microsoft-ds"}], deep=True)
        self.assertTrue({"smb-protocols", "smb-enum-shares", "default"} <= set(smb))
        self.assertEqual(sel([])[:2], ["vuln", "vulners"])

    def test_port_spec(self):
        self.assertEqual(netscan._port_spec([{"port": "80", "proto": "tcp"}, {"port": "22", "proto": "tcp"},
                                             {"port": "161", "proto": "udp"}]), ("T:22,80,U:161", True))

    def test_new_config_findings(self):
        cf = netscan.config_finding
        self.assertEqual(cf("smb-protocols", "dialects:\n  NT LM 0.12 (SMBv1) [dangerous, but default]")[0], "high")
        self.assertIsNone(cf("smb-protocols", "dialects:\n  2:0:2\n  3:1:1"))
        self.assertEqual(cf("vnc-info", "Protocol version: 3.8\nSecurity types:\n  None (1)")[0], "high")
        self.assertIsNone(cf("vnc-info", "Protocol version: 3.8\nSecurity types:\n  VNC Authentication (2)"))
        self.assertEqual(cf("http-methods", "Supported Methods: GET PUT\n  Potentially risky methods: PUT")[0], "medium")
        self.assertIsNone(cf("http-methods", "Potentially risky methods: TRACE"))
        self.assertEqual(cf("http-default-accounts", "[Cisco] at /\n    admin:admin")[0], "critical")
        self.assertEqual(cf("smb-enum-shares", "\\\\x\\pub:\n  Anonymous access: READ")[0], "medium")

    def test_info_scripts_go_to_port(self):
        xml = """<nmaprun><host><status state="up"/><ports>
            <port protocol="tcp" portid="80"><state state="open"/><service name="http"/>
              <script id="http-title" output="Hikvision Web Login - exploit-free"/></port></ports>
            <hostscript><script id="smb-os-discovery" output="&#10;  OS: Windows 10 Pro 19045&#10;  Computer name: PC"/></hostscript>
            </host></nmaprun>"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(xml)
        try:
            r = netscan.parse_host_scan(f.name, "10.0.0.2")
        finally:
            os.unlink(f.name)
        self.assertEqual(r["vulns"], [])  # "exploit" no título não vira achado
        self.assertIn("Hikvision", r["ports"][0]["scripts"]["http-title"])
        self.assertEqual(r["host_info"]["smb-os-discovery"], "Windows 10 Pro 19045")

    def test_cert_expiring(self):
        from datetime import datetime, timedelta
        soon = (datetime.now() + timedelta(days=10)).strftime("%Y-%m-%d")
        sev, title = netscan.config_finding("ssl-cert", f"Not valid after:  {soon}T00:00:00")
        self.assertEqual(sev, "low")
        self.assertIn("vence em", title)

    def test_service_scan_args(self):
        import argparse
        a = argparse.Namespace(target="192.168.0.0/24", ports=None, exclude="192.168.0.1", fast=True, deep=False,
                               udp=False, ipv6=True, no_ping=False, default_creds=False, offline=False,
                               workers=4, host_timeout=600, config=None)
        self.assertEqual(netscan.service_scan_args(a), ["-t", "192.168.0.0/24", "-x", "192.168.0.1", "--fast",
                                                        "--ipv6", "-w", "4", "--host-timeout", "600"])


if __name__ == "__main__":
    unittest.main()
