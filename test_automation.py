"""Testes da automação: python3 -m unittest test_automation"""
import http.server
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

import automation


def host(ip, mac=None, **kw):
    return {"ip": ip, "mac": mac, "ports": [], "vulns": [], **kw}


class TestInventory(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "inventario.json")

    def test_baseline_then_new_device(self):
        new, baseline = automation.update_inventory([host("10.0.0.1", "aa:bb:cc:00:00:01")], self.path, "t1")
        self.assertTrue(baseline)
        self.assertEqual(new, ["AA:BB:CC:00:00:01"])
        # mesmo aparelho com outro IP (DHCP) não é novo; outro MAC é
        hs = [host("10.0.0.9", "AA:BB:CC:00:00:01"), host("10.0.0.2", "aa:bb:cc:00:00:02")]
        new, baseline = automation.update_inventory(hs, self.path, "t2")
        self.assertFalse(baseline)
        self.assertEqual(new, ["AA:BB:CC:00:00:02"])
        inv = automation.load_inventory(self.path)
        d = inv["AA:BB:CC:00:00:01"]
        self.assertEqual((d["first_seen"], d["last_seen"], d["seen"]), ("t1", "t2", 2))
        self.assertEqual(d["ips"], ["10.0.0.1", "10.0.0.9"])
        self.assertEqual(hs[0]["first_seen"], "t1")

    def test_trusted_is_preserved(self):
        automation.update_inventory([host("10.0.0.1", "AA:00:00:00:00:01")], self.path, "t1")
        inv = automation.load_inventory(self.path)
        inv["AA:00:00:00:00:01"]["trusted"] = True
        with open(self.path, "w") as f:
            json.dump(inv, f)
        hs = [host("10.0.0.1", "AA:00:00:00:00:01")]
        automation.update_inventory(hs, self.path, "t2")
        self.assertTrue(hs[0]["trusted"])

    def test_corrupt_inventory_starts_over(self):
        with open(self.path, "w") as f:
            f.write("{quebrado")
        self.assertEqual(automation.load_inventory(self.path), {})


class TestAlerts(unittest.TestCase):
    def test_rules(self):
        hosts = [
            host("10.0.0.5", inv_key="K5", type_label="câmera", vendor="Hikvision"),
            host("10.0.0.6", inv_key="K6", trusted=True),
            host("10.0.0.7", inv_key="K7", vulns=[
                {"port": "445", "id": "smb-vuln-ms17-010", "kev": ["CVE-2017-0144"], "severity": "high"},
                {"port": "80", "id": "x", "severity": "low"}]),
        ]
        diff = {"new_hosts": [], "changed": {"10.0.0.7": {"new_ports": ["3389/tcp", "8080/tcp"],
                                                          "new_vulns": ["445:smb-vuln-ms17-010"]}}}
        alerts = automation.build_alerts(hosts, diff, new_keys={"K5", "K6"}, baseline=False)
        texts = " | ".join(a["text"] for a in alerts)
        self.assertEqual(alerts[0]["level"], "critical")      # KEV primeiro
        self.assertIn("10.0.0.5", texts)                      # aparelho novo e não confiável
        self.assertNotIn("10.0.0.6", texts)                   # novo mas marcado como confiável
        self.assertIn("3389/tcp", texts)
        self.assertNotIn("8080", texts)                       # porta comum não alerta
        self.assertNotIn("porta 80)", texts)                  # achado baixo não alerta

    def test_baseline_has_no_intruder_alert(self):
        alerts = automation.build_alerts([host("10.0.0.5", inv_key="K5")], None, {"K5"}, baseline=True)
        self.assertEqual(alerts, [])

    def test_old_vuln_not_repeated(self):
        h = host("10.0.0.7", vulns=[{"port": "445", "id": "v", "severity": "critical"}])
        diff = {"new_hosts": [], "changed": {}}
        self.assertEqual(automation.build_alerts([h], diff), [])  # já existia na anterior


class TestServiceAndFiles(unittest.TestCase):
    def test_units(self):
        svc, timer = automation.service_units("/opt/a b/netscan.py", 30, ["-t", "192.168.0.0/24", "--fast"], "/usr/bin/python3")
        self.assertIn("ExecStart=/usr/bin/python3 '/opt/a b/netscan.py' --compare latest --notify --keep 100 -t 192.168.0.0/24 --fast", svc)
        self.assertIn("EnvironmentFile=-/etc/netscan.env", svc)
        self.assertIn("OnUnitActiveSec=30min", timer)

    def test_install_requires_root(self):
        with mock.patch("os.geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                automation.install_service("x.py", 30, [])

    def test_prune_and_latest(self):
        d = tempfile.mkdtemp()
        for name in ["resultados_2026-01-01_000000", "resultados_2026-01-02_000000", "resultados_2026-01-03_000000"]:
            os.makedirs(os.path.join(d, name))
            open(os.path.join(d, name, "relatorio.json"), "w").close()
        os.makedirs(os.path.join(d, "outra_pasta"))
        self.assertTrue(automation.latest_report(d).endswith("2026-01-03_000000/relatorio.json"))
        self.assertEqual(automation.prune_results(d, 2), 1)
        self.assertEqual(sorted(os.listdir(d)), ["outra_pasta", "resultados_2026-01-02_000000", "resultados_2026-01-03_000000"])


class TestNotify(unittest.TestCase):
    def test_webhook_json_and_ntfy(self):
        got = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                got.append((self.path, self.headers["Content-Type"], self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        alerts = [{"level": "high", "ip": "10.0.0.5", "text": "Dispositivo nunca visto"}]
        env = {"NETSCAN_WEBHOOK": base + "/hook"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(automation.notify(alerts, "1 alerta"), ["webhook"])
        with mock.patch.dict(os.environ, {"NETSCAN_WEBHOOK": base + "/ntfy-topico"}, clear=True):
            automation.notify(alerts)
        srv.shutdown()
        srv.server_close()
        self.assertEqual(json.loads(got[0][2])["content"].splitlines()[1], "• [HIGH] Dispositivo nunca visto")
        self.assertTrue(got[1][1].startswith("text/plain"))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(automation.notify(alerts), [])  # nada configurado: não envia nada

    def test_webhook_failure_does_not_raise(self):
        with mock.patch.dict(os.environ, {"NETSCAN_WEBHOOK": "http://127.0.0.1:9/nada"}, clear=True):
            self.assertEqual(automation.notify([{"level": "low", "ip": "x", "text": "t"}]), [])


if __name__ == "__main__":
    unittest.main()
