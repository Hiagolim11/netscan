"""Testes do bot do Telegram (API e scanner falsos): python3 -m unittest test_telegram_bot"""
import json
import os
import tempfile
import unittest
from unittest import mock

import automation
import telegram_bot

CHAT = "42"


class FakeScanner:
    def __init__(self):
        self.listeners = []
        self.started = []
        self.running = False

    def start(self, opts, origin="manual"):
        if self.running:
            return {"ok": False, "error": "Já existe uma varredura em andamento."}
        self.started.append((opts, origin))
        self.running = True
        return {"ok": True}

    def emit(self, data):
        for fn in self.listeners:
            fn({"type": "event", "data": data})


class FakeScheduler:
    next_run = 123

    def __init__(self, settings):
        self.settings = settings

    def status(self):
        sch = automation.load_settings(self.settings)["schedule"]
        return {"every": sch["every"], "paused": sch["paused"], "next": "10:30"}


class TestBot(unittest.TestCase):
    def setUp(self):
        self.data = tempfile.mkdtemp()
        self.settings = os.path.join(self.data, "settings.json")
        automation.save_settings({"scan": {"target": "10.0.0.0/24", "workers": 4},
                                  "schedule": {"every": 60},
                                  "integrations": {"telegram_token": "1:x", "telegram_chat": CHAT}}, self.settings)
        self.calls = []
        self.scanner = FakeScanner()
        self.hist = []
        self.bot = telegram_bot.TelegramBot(self.settings, self.data, self.scanner, FakeScheduler(self.settings),
                                            lambda: self.hist, log=lambda *a: None, api=self.api)

    def api(self, method, params=None, files=None):
        self.calls.append((method, params or {}, files))
        return {"ok": True, "result": []}

    def sent(self):
        return [p["text"] for m, p, _ in self.calls if m == "sendMessage"]

    def msg(self, text, chat=CHAT):
        self.bot.handle_update({"update_id": 1, "message": {"chat": {"id": int(chat)}, "text": text}}, CHAT)

    def click(self, data, chat=CHAT):
        self.bot.handle_update({"update_id": 2, "callback_query": {"id": "q", "data": data,
                                                                   "message": {"chat": {"id": int(chat)}}}}, CHAT)

    def test_ignores_other_chats(self):
        self.msg("/verificar", chat="999")
        self.click("scan", chat="999")
        self.msg("/pausar", chat="999")
        self.assertEqual(self.scanner.started, [])
        self.assertEqual(self.sent(), [])
        self.assertFalse(automation.load_settings(self.settings)["schedule"]["paused"])

    def test_start_from_unknown_chat_reveals_only_its_own_id(self):
        self.msg("/start", chat="555")
        self.assertIn("Seu id de chat é: 555", self.sent()[-1])
        self.assertNotIn(CHAT, self.sent()[-1])       # nunca revela o chat autorizado
        self.assertEqual(self.scanner.started, [])

    def test_quick_scan_whole_network(self):
        self.msg("/verificar")
        opts, origin = self.scanner.started[0]
        self.assertEqual((opts["target"], opts["fast"], opts["compare"], origin), ("10.0.0.0/24", True, "latest", "telegram"))
        self.assertNotIn("single", opts)
        self.assertIn("10.0.0.0/24", self.sent()[-1])

    def test_scan_one_ip_is_single_and_full(self):
        self.msg("/verificar_completa 10.0.0.7")
        opts, _ = self.scanner.started[0]
        self.assertEqual((opts["target"], opts["fast"], opts.get("single"), opts["compare"]), ("10.0.0.7", False, True, ""))

    def test_rejects_bad_target(self):
        for bad in ["10.0.0.1;rm -rf /", "$(id)", "a b", "x" * 300]:
            self.msg("/verificar " + bad)
        self.assertEqual(self.scanner.started, [])
        self.assertIn("Alvo inválido", self.sent()[-1])

    def test_busy_scanner(self):
        self.scanner.running = True
        self.msg("/verificar")
        self.assertIn("andamento", self.sent()[-1])

    def test_result_sent_to_requester(self):
        self.click("scan")
        self.scanner.emit({"event": "done", "hosts": [{"ip": "10.0.0.1"}], "alerts": [{"level": "high", "text": "Dispositivo nunca visto"}],
                           "analysis": {"risk": 70, "level": "high", "label": "alto",
                                        "top": [{"score": 70, "title": "Telnet", "ip": "10.0.0.1", "port": "23", "fix": "Desative"}]}})
        text = self.sent()[-1]
        self.assertIn("ALTO (70/100)", text)
        self.assertIn("Dispositivo nunca visto", text)
        self.assertIn("↳ Desative", text)
        n = len(self.sent())
        self.scanner.emit({"event": "done", "hosts": []})   # varredura seguinte (agendada): não responde de novo
        self.assertEqual(len(self.sent()), n)

    def test_single_ip_result(self):
        self.msg("/verificar 10.0.0.7")
        self.scanner.emit({"event": "done", "hosts": [{"ip": "10.0.0.7", "type_label": "câmera", "risk": 76,
                                                         "ports": [{"port": "554", "proto": "tcp", "service": "rtsp"}],
                                                         "vulns": [{"severity": "critical", "title": "Senha padrão", "port": "80"}]}]})
        text = self.sent()[-1]
        self.assertIn("10.0.0.7 — câmera", text)
        self.assertIn("554/tcp rtsp", text)
        self.assertIn("[CRITICAL] Senha padrão", text)

    def test_pause_resume(self):
        self.msg("/pausar")
        self.assertTrue(automation.load_settings(self.settings)["schedule"]["paused"])
        self.msg("/status")
        self.assertIn("pausado", self.sent()[-1])
        self.msg("/retomar")
        self.assertFalse(automation.load_settings(self.settings)["schedule"]["paused"])
        self.assertEqual(automation.load_settings(self.settings)["schedule"]["every"], 60)

    def test_trust_button(self):
        inv = os.path.join(self.data, "inventario.json")
        with open(inv, "w") as f:
            json.dump({"AA:BB:CC:DD:EE:01": {"trusted": False, "ips": ["10.0.0.9"], "type_label": "câmera"}}, f)
        self.click("trust:AA:BB:CC:DD:EE:01")
        self.assertTrue(automation.load_inventory(inv)["AA:BB:CC:DD:EE:01"]["trusted"])
        self.click("trust:../../etc/passwd")          # chave inválida: ignorada
        self.assertIn("confiável", self.sent()[-1])

    def test_summary_report_and_devices(self):
        self.msg("/ultimo")
        self.assertIn("Ainda não há varreduras", self.sent()[-1])
        name = "resultados_2026-11-03_080000"
        os.makedirs(os.path.join(self.data, name))
        report = {"target": "10.0.0.0/24", "timestamp": "2026-11-03 08:00:00",
                  "hosts": [{"ip": "10.0.0.1", "type_label": "roteador", "risk": 90, "risk_level": "critical"},
                            {"ip": "10.0.0.2", "type_label": "celular / tablet", "risk": 0, "trusted": True}],
                  "analysis": {"risk": 90, "level": "critical", "label": "crítico", "top": []}}
        with open(os.path.join(self.data, name, "relatorio.json"), "w") as f:
            json.dump(report, f)
        with open(os.path.join(self.data, name, "relatorio.html"), "w") as f:
            f.write("<html>netscan</html>")
        self.hist[:] = [{"name": name, "timestamp": report["timestamp"], "hosts": 2, "risk": 90}]
        self.msg("/ultimo")
        self.assertIn("CRÍTICO (90/100)", self.sent()[-1])
        self.msg("/aparelhos")
        self.assertTrue(self.sent()[-1].index("10.0.0.1") < self.sent()[-1].index("10.0.0.2"))  # mais arriscado primeiro
        self.click("report")
        doc = [c for c in self.calls if c[0] == "sendDocument"][-1]
        self.assertEqual(doc[2]["document"][1], b"<html>netscan</html>")

    def test_help_has_buttons(self):
        self.msg("/start")
        params = [p for m, p, _ in self.calls if m == "sendMessage"][-1]
        self.assertIn("/verificar", params["text"])
        self.assertEqual(params["reply_markup"]["inline_keyboard"][0][0]["callback_data"], "scan")


class TestAlertButtons(unittest.TestCase):
    def test_keyboard_has_trust_for_unknown_devices(self):
        kb = automation.alert_keyboard([{"ip": "10.0.0.9", "key": "AA:BB:CC:DD:EE:01", "level": "high"},
                                        {"ip": "10.0.0.1", "level": "critical"}])
        data = [b["callback_data"] for row in kb["inline_keyboard"] for b in row]
        self.assertEqual(data, ["scan", "summary", "trust:AA:BB:CC:DD:EE:01"])
        self.assertTrue(all(len(d) <= 64 for d in data))  # limite do Telegram

    def test_buttons_only_when_server_sets_env(self):
        bodies = []
        alerts = [{"level": "high", "ip": "x", "text": "t", "key": "AA:BB:CC:DD:EE:01"}]
        cfg = {"telegram_token": "1:x", "telegram_chat": "42", "min_level": "low"}
        with mock.patch.object(automation, "_post", lambda url, body, ct: bodies.append(body.decode())):
            with mock.patch.dict(os.environ, {}, clear=True):
                automation.notify(alerts, config=cfg)
            with mock.patch.dict(os.environ, {"NETSCAN_TELEGRAM_BUTTONS": "1"}, clear=True):
                automation.notify(alerts, config=cfg)
        self.assertNotIn("reply_markup", bodies[0])
        self.assertIn("reply_markup", bodies[1])


if __name__ == "__main__":
    unittest.main()
