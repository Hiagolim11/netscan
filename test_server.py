"""Testes do servidor web (sobe o server.py de verdade): python3 -m unittest test_server

A varredura de teste é só em 127.0.0.1, no modo rápido.
"""
import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tempfile.mkdtemp()
        cls.port = free_port()
        env = dict(os.environ, NETSCAN_DATA=cls.data, NETSCAN_PORT=str(cls.port), NETSCAN_BIND="127.0.0.1",
                   NETSCAN_PASSWORD="segredo-teste", HOME=cls.data)
        cls.proc = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py")], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.base = f"http://127.0.0.1:{cls.port}"
        for _ in range(50):
            try:
                urllib.request.urlopen(cls.base + "/login.html", timeout=1)
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=10)

    def client(self, login=True):
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())
        if login:
            code, _ = self.call(opener, "POST", "/api/login", {"password": "segredo-teste"})
            self.assertEqual(code, 200)
        return opener

    def call(self, opener, method, path, body=None, csrf=True):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if csrf:
            req.add_header("X-Netscan", "1")
        try:
            with opener.open(req, timeout=30) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if r.headers.get_content_type() == "application/json" else raw)
        except urllib.error.HTTPError as e:
            with e:
                raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw

    def test_auth_required(self):
        anon = self.client(login=False)
        self.assertEqual(self.call(anon, "GET", "/api/settings")[0], 401)
        self.assertEqual(self.call(anon, "GET", "/")[0], 302)            # página -> login
        self.assertEqual(self.call(anon, "GET", "/login.html")[0], 200)  # login é público
        code, body = self.call(anon, "POST", "/api/login", {"password": "errada"})
        self.assertEqual((code, body["ok"]), (401, False))

    def test_csrf_header_required(self):
        c = self.client()
        self.assertEqual(self.call(c, "POST", "/api/scan/stop", {}, csrf=False)[0], 403)

    def test_settings_hide_token(self):
        c = self.client()
        code, body = self.call(c, "POST", "/api/settings", {
            "scan": {"mode": "fast", "workers": 3},
            "schedule": {"every": 30},
            "integrations": {"telegram_token": "123:SECRETO", "telegram_chat": "42", "min_level": "high"}})
        self.assertEqual(code, 200)
        self.assertEqual(body["settings"]["integrations"]["telegram_token"], "")
        self.assertTrue(body["settings"]["integrations"]["telegram_token_set"])
        # salvar de novo com o campo vazio mantém o token
        self.call(c, "POST", "/api/settings", {"integrations": {"telegram_chat": "43"}})
        with open(os.path.join(self.data, "settings.json")) as f:
            saved = json.load(f)
        self.assertEqual(saved["integrations"]["telegram_token"], "123:SECRETO")
        self.assertEqual(oct(os.stat(os.path.join(self.data, "settings.json")).st_mode & 0o777), "0o600")
        info = self.call(c, "GET", "/api/info")[1]
        self.assertEqual(info["scheduler"]["every"], 30)
        self.call(c, "POST", "/api/settings", {"schedule": {"every": 0}})

    def test_static_and_report_paths_are_confined(self):
        c = self.client()
        self.assertEqual(self.call(c, "GET", "/index.html")[0], 200)
        self.assertEqual(self.call(c, "GET", "/../server.py")[0], 404)
        self.assertEqual(self.call(c, "GET", "/%2e%2e/server.py")[0], 404)
        self.assertEqual(self.call(c, "GET", "/api/report/..%2F..%2Fetc/passwd")[0], 404)
        self.assertEqual(self.call(c, "GET", "/api/report/resultados_x/settings.json")[0], 404)
        self.assertEqual(self.call(c, "GET", "/api/history/..")[0], 404)

    def test_notify_test_without_integrations(self):
        c = self.client()
        code, body = self.call(c, "POST", "/api/notify/test", {})
        self.assertEqual(code, 200)
        self.assertEqual(body["sent"], [])

    def test_full_scan_flow(self):
        c = self.client()
        code, body = self.call(c, "POST", "/api/scan/start", {"opts": {"target": "127.0.0.1", "fast": True, "ports": "1-1000"}})
        self.assertTrue(body["ok"], body)
        self.assertFalse(self.call(c, "POST", "/api/scan/start", {"opts": {"target": "127.0.0.1"}})[1]["ok"])  # uma por vez
        # acompanha pelo SSE até o fim
        req = urllib.request.Request(self.base + "/api/events")
        events = []
        with c.open(req, timeout=180) as r:
            for raw in r:
                line = raw.decode().strip()
                if not line.startswith("data: "):
                    continue
                msg = json.loads(line[6:])
                events.append(msg)
                if msg["type"] == "close":
                    break
        kinds = [m["data"].get("event") for m in events if m["type"] == "event"]
        self.assertIn("start", kinds)
        self.assertIn("done", kinds)
        self.assertEqual(events[-1]["data"]["code"], 0)
        done = next(m["data"] for m in events if m["type"] == "event" and m["data"].get("event") == "done")
        self.assertIn("analysis", done)
        name = os.path.basename(done["outdir"])
        hist = self.call(c, "GET", "/api/history")[1]
        self.assertEqual(hist[0]["name"], name)
        self.assertTrue(self.call(c, "GET", f"/api/history/{name}")[1]["ok"])
        code, html = self.call(c, "GET", f"/api/report/{name}/relatorio.html")
        self.assertEqual(code, 200)
        self.assertIn(b"netscan", html)
        key = done["hosts"][0]["inv_key"] if done["hosts"] else None
        if key:
            self.assertTrue(self.call(c, "POST", "/api/inventory/trust", {"key": key, "trusted": True})[1]["ok"])
        self.assertEqual(self.call(c, "POST", "/api/inventory/trust", {"key": "../x", "trusted": True})[0], 400)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


if __name__ == "__main__":
    unittest.main()
