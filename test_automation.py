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


class TestSettings(unittest.TestCase):
    def test_merge_validate_and_permissions(self):
        path = os.path.join(tempfile.mkdtemp(), "settings.json")
        automation.save_settings({"scan": {"workers": 4}, "schedule": {"every": 30}}, path)
        # atualização parcial não apaga as outras seções; tipos errados e chaves estranhas são ignorados
        s = automation.save_settings({"integrations": {"webhook": "https://ntfy.sh/x", "desktop": "sim"},
                                      "scan": {"udp": 1, "workers": True}, "outra": {"x": 1}}, path)
        self.assertEqual((s["scan"]["workers"], s["schedule"]["every"]), (4, 30))
        self.assertEqual(s["integrations"]["webhook"], "https://ntfy.sh/x")
        self.assertTrue(s["integrations"]["desktop"])   # "sim" não é bool: mantém o padrão
        self.assertFalse(s["scan"]["udp"])              # 1 não é bool
        self.assertNotIn("outra", automation.load_settings(path))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertTrue(automation.has_integrations(s))

    def test_min_level_filter(self):
        got = []
        with mock.patch.object(automation, "_post", lambda url, body, ct: got.append(body)):
            sent = automation.notify([{"level": "low", "ip": "x", "text": "baixo"}], config={"webhook": "http://h", "min_level": "high"})
            self.assertEqual((sent, got), ([], []))
            sent = automation.notify([{"level": "critical", "ip": "x", "text": "grave"}], config={"webhook": "http://h", "min_level": "high"})
            self.assertEqual(sent, ["webhook"])


class TestTelegramErrors(unittest.TestCase):
    def err(self, code, desc):
        import io
        import urllib.error
        body = json.dumps({"ok": False, "error_code": code, "description": desc}).encode()
        return urllib.error.HTTPError("https://api.telegram.org/bot123:SECRETO/sendMessage", code, "x", {}, io.BytesIO(body))

    def test_reasons_are_readable_and_hide_token(self):
        cases = [(401, "Unauthorized", "token inválido"), (404, "Not Found", "token inválido"),
                 (400, "Bad Request: chat not found", "chat não encontrado"),
                 (403, "Forbidden: bot can't initiate conversation with a user", "envie /start"),
                 (403, "Forbidden: bot was blocked by the user", "desbloqueie")]
        for code, desc, expect in cases:
            msg = automation.telegram_error(self.err(code, desc))
            self.assertIn(expect, msg)
            self.assertIn(f"HTTP {code}", msg)
            self.assertNotIn("SECRETO", msg)

    def test_bot_id_as_chat_is_caught_without_calling_api(self):
        logs = []
        with mock.patch.object(automation, "_post") as post:
            sent = automation.notify([{"level": "high", "ip": "x", "text": "t"}], log=lambda m, l="*": logs.append(m),
                                     config={"telegram_token": "123456:SECRETO", "telegram_chat": "123456", "min_level": "low"})
        post.assert_not_called()
        self.assertEqual(sent, [])
        self.assertIn("próprio bot", logs[0])
        msg = automation.telegram_error(self.err(403, "Forbidden: the bot can't send messages to the bot"))
        self.assertIn("próprio bot", msg)

    def test_notify_reports_reason(self):
        logs = []
        with mock.patch.object(automation, "_post", side_effect=self.err(400, "Bad Request: chat not found")):
            sent = automation.notify([{"level": "high", "ip": "x", "text": "t"}],
                                     log=lambda m, l="*": logs.append(m),
                                     config={"telegram_token": "123:SECRETO", "telegram_chat": "@eu", "min_level": "low"})
        self.assertEqual(sent, [])
        self.assertIn("chat não encontrado", logs[0])
        self.assertNotIn("SECRETO", logs[0])


if __name__ == "__main__":
    unittest.main()
