#!/usr/bin/env python3
"""netscan — servidor web para rodar em Docker (Umbrel, NAS, servidor doméstico).

Serve a mesma interface do app desktop no navegador, com login por senha, varreduras
disparadas remotamente, eventos ao vivo (SSE), agendamento interno, histórico, relatórios,
inventário e configurações das integrações.

Variáveis de ambiente:
  NETSCAN_PASSWORD  senha de acesso (no Umbrel: $APP_PASSWORD). Sem ela, uma senha aleatória
                    é gerada no primeiro início, salva em $NETSCAN_DATA/.password e mostrada no log.
  NETSCAN_DATA      pasta de dados (padrão /data)
  NETSCAN_PORT      porta HTTP (padrão 7765)
  NETSCAN_BIND      endereço de escuta (padrão 0.0.0.0)
  NETSCAN_KEEP      quantas varreduras manter (padrão 100)
"""
import hmac
import json
import os
import queue
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import automation

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "renderer")
NETSCAN = os.path.join(HERE, "netscan.py")
DATA = os.path.abspath(os.environ.get("NETSCAN_DATA", "/data"))
PORT = int(os.environ.get("NETSCAN_PORT", "7765"))
BIND = os.environ.get("NETSCAN_BIND", "0.0.0.0")
KEEP = int(os.environ.get("NETSCAN_KEEP", "100"))
SETTINGS = os.path.join(DATA, "settings.json")
INVENTORY = os.path.join(DATA, "inventario.json")

SESSION_TTL = 7 * 86400
COOKIE = "netscan_session"
DIR_RE = re.compile(r"^(resultados|rescan)_[\w-]+$")
KEY_RE = re.compile(r"^[0-9A-F:.]{7,45}$", re.I)
REPORT_TYPES = {
    "relatorio.html": "text/html; charset=utf-8", "relatorio.csv": "text/csv; charset=utf-8",
    "relatorio.json": "application/json", "relatorio.txt": "text/plain; charset=utf-8",
    "relatorio.pdf": "application/pdf",
}
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8", ".png": "image/png", ".svg": "image/svg+xml"}
PUBLIC = {"/login.html", "/styles.css", "/login.js"}


def log(msg):
    print(f"[netscan] {datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


# ---------------- senha e sessões ----------------

def load_password():
    pw = os.environ.get("NETSCAN_PASSWORD", "")
    if pw:
        return pw
    path = os.path.join(DATA, ".password")
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        pw = secrets.token_urlsafe(12)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw)
        log(f"Nenhuma NETSCAN_PASSWORD definida. Senha gerada: {pw}  (salva em {path})")
        return pw


class Sessions:
    def __init__(self):
        self.tokens = {}
        self.lock = threading.Lock()

    def new(self):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            self.tokens[tok] = time.time() + SESSION_TTL
        return tok

    def valid(self, tok):
        with self.lock:
            exp = self.tokens.get(tok or "")
            if exp and exp > time.time():
                return True
            self.tokens.pop(tok or "", None)
            return False

    def drop(self, tok):
        with self.lock:
            self.tokens.pop(tok or "", None)


# ---------------- varreduras ----------------

def build_args(o):
    """Opções da interface -> argumentos do netscan.py (validados de novo pelo próprio netscan.py)."""
    a = [sys.executable, NETSCAN, "--json-stream", "--config", SETTINGS, "--notify", "--keep", str(KEEP)]
    if o.get("target"):
        a += ["-t", str(o["target"])]
    if o.get("fast"):
        a.append("--fast")
    if o.get("deep"):
        a.append("--deep")
    for key, flag in (("ports", "-p"), ("exclude", "-x")):
        if o.get(key):
            a += [flag, str(o[key])]
    for key, flag in (("udp", "--udp"), ("noPing", "--no-ping"), ("ipv6", "--ipv6"), ("defaultCreds", "--default-creds")):
        if o.get(key):
            a.append(flag)
    try:
        a += ["-w", str(min(16, max(1, int(o.get("workers") or 1))))]
    except (TypeError, ValueError):
        pass
    if o.get("single"):
        a += ["-o", os.path.join(DATA, f"rescan_{datetime.now():%Y%m%d_%H%M%S}")]
    cmp_ = o.get("compare")
    if cmp_ == "latest":
        a += ["--compare", "latest"]
    elif cmp_ and DIR_RE.match(str(cmp_)) and os.path.exists(os.path.join(DATA, cmp_, "relatorio.json")):
        a += ["--compare", os.path.join(DATA, cmp_, "relatorio.json")]
    return a


def opts_from_settings(s):
    sc = s["scan"]
    return {"target": sc["target"], "fast": sc["mode"] == "fast", "deep": sc["mode"] == "deep",
            "ports": sc["ports"], "exclude": sc["exclude"], "workers": sc["workers"], "udp": sc["udp"],
            "noPing": sc["noPing"], "ipv6": sc["ipv6"], "defaultCreds": sc["defaultCreds"], "compare": "latest"}


class Scanner:
    """Uma varredura por vez; eventos vão para todos os navegadores conectados."""

    def __init__(self):
        self.proc = None
        self.lock = threading.Lock()
        self.buffer = []          # eventos da varredura atual/última: quem abre a página depois vê tudo
        self.clients = set()

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def subscribe(self):
        q = queue.Queue()
        with self.lock:
            self.clients.add(q)
            backlog = list(self.buffer)
        return q, backlog

    def unsubscribe(self, q):
        with self.lock:
            self.clients.discard(q)

    def broadcast(self, kind, data):
        msg = {"type": kind, "data": data}
        with self.lock:
            self.buffer.append(msg)
            del self.buffer[:-5000]
            for q in self.clients:
                q.put(msg)

    def start(self, opts, origin="manual"):
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                return {"ok": False, "error": "Já existe uma varredura em andamento."}
            self.buffer = []
            try:
                # sessão própria: parar mata o netscan.py e todos os nmap filhos de uma vez
                self.proc = subprocess.Popen(build_args(opts), cwd=DATA, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True, start_new_session=True)
            except OSError as e:
                return {"ok": False, "error": str(e)}
            proc = self.proc
        log(f"Varredura iniciada ({origin}).")
        threading.Thread(target=self._pump_stdout, args=(proc,), daemon=True).start()
        threading.Thread(target=self._pump_stderr, args=(proc,), daemon=True).start()
        return {"ok": True}

    def _pump_stdout(self, proc):
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.broadcast("event", json.loads(line))
            except ValueError:
                pass
        code = proc.wait()
        self.broadcast("close", {"code": code})
        log(f"Varredura terminou (código {code}).")

    def _pump_stderr(self, proc):
        for line in proc.stderr:
            if line.strip():
                self.broadcast("log", line.strip())

    def stop(self):
        proc = self.proc
        if proc is None or proc.poll() is not None:
            return False
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except OSError:
            proc.terminate()
        return True


class Scheduler(threading.Thread):
    """Varredura automática a cada N minutos (substitui o timer do systemd dentro do container)."""

    def __init__(self, scanner):
        super().__init__(daemon=True)
        self.scanner = scanner
        self.next_run = None

    def status(self):
        every = automation.load_settings(SETTINGS)["schedule"]["every"]
        nxt = datetime.fromtimestamp(self.next_run).strftime("%H:%M") if every and self.next_run else None
        return {"every": every, "next": nxt}

    def run(self):
        while True:
            s = automation.load_settings(SETTINGS)
            every = s["schedule"]["every"]
            if every < 5:
                self.next_run = None
            elif self.next_run is None:
                self.next_run = time.time() + every * 60
            elif time.time() >= self.next_run:
                if not self.scanner.running:  # manual em andamento: tenta de novo no próximo ciclo
                    self.scanner.start(opts_from_settings(s), origin="agendada")
                    self.next_run = time.time() + every * 60
            time.sleep(20)


# ---------------- HTTP ----------------

def public_settings(s):
    """Nunca devolve o token do Telegram ao navegador: só se há um salvo."""
    s = json.loads(json.dumps(s))
    s["integrations"]["telegram_token_set"] = bool(s["integrations"]["telegram_token"])
    s["integrations"]["telegram_token"] = ""
    return s


def history_list():
    out = []
    try:
        names = sorted((d for d in os.listdir(DATA) if d.startswith("resultados_")), reverse=True)[:40]
    except OSError:
        names = []
    for name in names:
        try:
            with open(os.path.join(DATA, name, "relatorio.json")) as f:
                r = json.load(f)
        except (OSError, ValueError):
            continue
        out.append({"name": name, "timestamp": r.get("timestamp"), "target": r.get("target"),
                    "hosts": len(r.get("hosts", [])), "totals": r.get("totals", {}),
                    "risk": (r.get("analysis") or {}).get("risk"), "alerts": len(r.get("alerts", []))})
    return out


def make_handler(password, sessions, scanner, scheduler):
    class Handler(BaseHTTPRequestHandler):
        server_version = "netscan"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass  # sem log de cada requisição (o SSE geraria ruído)

        # ---- utilidades ----
        def _session(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE:
                    return v
            return None

        def _authed(self):
            return sessions.valid(self._session())

        def _send(self, code, body=b"", ctype="application/json", headers=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json_body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if n > 1_000_000:
                    return None
                return json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return None

        def _static(self, path):
            rel = "index.html" if path in ("/", "") else path.lstrip("/")
            full = os.path.realpath(os.path.join(STATIC, rel))
            if not full.startswith(os.path.realpath(STATIC) + os.sep) or not os.path.isfile(full):
                return self._send(404, {"error": "não encontrado"})
            with open(full, "rb") as f:
                self._send(200, f.read(), STATIC_TYPES.get(os.path.splitext(full)[1], "application/octet-stream"))

        # ---- GET ----
        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path in PUBLIC:
                return self._static(path)
            if not self._authed():
                if path.startswith("/api/"):
                    return self._send(401, {"error": "login necessário"})
                return self._send(302, b"", "text/plain", {"Location": "/login.html"})
            if path == "/api/info":
                return self._send(200, {"platform": "web", "running": scanner.running, "scheduler": scheduler.status()})
            if path == "/api/settings":
                return self._send(200, public_settings(automation.load_settings(SETTINGS)))
            if path == "/api/history":
                return self._send(200, history_list())
            m = re.match(r"^/api/history/([^/]+)$", path)
            if m:
                name = m.group(1)
                f = os.path.join(DATA, name, "relatorio.json")
                if not DIR_RE.match(name) or not os.path.exists(f):
                    return self._send(404, {"ok": False, "error": "Relatório não encontrado."})
                with open(f) as fh:
                    return self._send(200, {"ok": True, "report": json.load(fh), "outdir": os.path.join(DATA, name)})
            m = re.match(r"^/api/report/([^/]+)/([^/]+)$", path)
            if m:
                name, fname = m.groups()
                f = os.path.join(DATA, name, fname)
                if not DIR_RE.match(name) or fname not in REPORT_TYPES or not os.path.isfile(f):
                    return self._send(404, {"error": "arquivo não encontrado"})
                with open(f, "rb") as fh:
                    disp = "inline" if fname.endswith((".html", ".pdf", ".txt")) else "attachment"
                    return self._send(200, fh.read(), REPORT_TYPES[fname],
                                      {"Content-Disposition": f'{disp}; filename="{name}-{fname}"'})
            if path == "/api/events":
                return self._events()
            return self._static(path)

        def _events(self):
            q, backlog = scanner.subscribe()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                for msg in backlog:
                    self.wfile.write(f"data: {json.dumps(msg, ensure_ascii=False)}\n\n".encode())
                self.wfile.write(f"data: {json.dumps({'type': 'ready', 'data': {'running': scanner.running}})}\n\n".encode())
                self.wfile.flush()
                while True:
                    try:
                        msg = q.get(timeout=15)
                        self.wfile.write(f"data: {json.dumps(msg, ensure_ascii=False)}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")  # mantém a conexão viva atrás de proxies
                    self.wfile.flush()
            except (OSError, ValueError):
                pass
            finally:
                scanner.unsubscribe(q)

        # ---- POST/PUT ----
        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            # cabeçalho próprio: navegador não envia de outro site sem CORS (proteção CSRF)
            if self.headers.get("X-Netscan") != "1":
                return self._send(403, {"error": "requisição recusada"})
            if path == "/api/login":
                body = self._json_body() or {}
                if hmac.compare_digest(str(body.get("password", "")).encode(), password.encode()):
                    tok = sessions.new()
                    return self._send(200, {"ok": True}, headers={
                        "Set-Cookie": f"{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"})
                time.sleep(1)  # freia tentativa e erro
                return self._send(401, {"ok": False, "error": "Senha incorreta."})
            if not self._authed():
                return self._send(401, {"error": "login necessário"})
            body = self._json_body()
            if body is None:
                return self._send(400, {"error": "JSON inválido"})
            if path == "/api/logout":
                sessions.drop(self._session())
                return self._send(200, {"ok": True}, headers={"Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0"})
            if path == "/api/scan/start":
                return self._send(200, scanner.start(body.get("opts") or {}))
            if path == "/api/scan/stop":
                return self._send(200, {"ok": scanner.stop()})
            if path == "/api/settings":
                cur = automation.load_settings(SETTINGS)
                integ = body.get("integrations") or {}
                if not integ.get("telegram_token"):  # campo vazio = manter o token salvo
                    integ["telegram_token"] = cur["integrations"]["telegram_token"]
                body["integrations"] = integ
                saved = automation.save_settings(body, SETTINGS)
                scheduler.next_run = None  # recalcula a próxima execução com o intervalo novo
                return self._send(200, {"ok": True, "settings": public_settings(saved)})
            if path == "/api/notify/test":
                out = subprocess.run([sys.executable, NETSCAN, "--json-stream", "--test-notify", "--config", SETTINGS],
                                     cwd=DATA, capture_output=True, text=True, timeout=60)
                try:
                    return self._send(200, json.loads(out.stdout.strip().splitlines()[-1]))
                except (ValueError, IndexError):
                    return self._send(500, {"sent": [], "errors": ["falha ao testar"]})
            if path == "/api/inventory/trust":
                key = str(body.get("key", ""))
                if not KEY_RE.match(key):
                    return self._send(400, {"ok": False})
                inv = automation.load_inventory(INVENTORY)
                if key not in inv:
                    return self._send(404, {"ok": False, "error": "Aparelho não está no inventário."})
                inv[key]["trusted"] = bool(body.get("trusted"))
                tmp = INVENTORY + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(inv, f, indent=1, ensure_ascii=False)
                os.replace(tmp, INVENTORY)
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "não encontrado"})

    return Handler


def main():
    os.makedirs(DATA, exist_ok=True)
    password = load_password()
    sessions = Sessions()
    scanner = Scanner()
    scheduler = Scheduler(scanner)
    scheduler.start()
    httpd = ThreadingHTTPServer((BIND, PORT), make_handler(password, sessions, scanner, scheduler))
    httpd.daemon_threads = True

    def shutdown(*_):
        scanner.stop()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    log(f"Interface em http://{BIND}:{PORT}  ·  dados em {DATA}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
