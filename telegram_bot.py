"""netscan — bot do Telegram com comandos e botões (roda dentro do server.py).

Usa long polling (getUpdates): o servidor pergunta ao Telegram se há mensagens novas, então
não precisa de porta aberta nem endereço público — funciona atrás do roteador (Umbrel).
Só responde ao chat configurado em Preferências → Integrações; o resto é ignorado.
"""
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import uuid

import automation

TARGET_RE = re.compile(r"^[A-Za-z0-9.\-/,:]+$")
KEY_RE = re.compile(r"^[0-9A-F:.]{7,45}$", re.I)
LEVEL_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "none": "🟢"}

COMMANDS = [
    ("verificar", "Varredura rápida (ou: /verificar 192.168.0.10)"),
    ("verificar_completa", "Varredura com checagens de vulnerabilidade"),
    ("status", "Varredura em andamento e próxima agendada"),
    ("ultimo", "Resumo da última varredura"),
    ("aparelhos", "Aparelhos da rede com tipo e risco"),
    ("relatorio", "Envia o relatório da última varredura"),
    ("pausar", "Pausa a varredura agendada"),
    ("retomar", "Retoma a varredura agendada"),
    ("ajuda", "Lista os comandos"),
]

MAIN_KEYBOARD = {"inline_keyboard": [
    [{"text": "🔍 Verificar agora", "callback_data": "scan"}, {"text": "📊 Resumo", "callback_data": "summary"}],
    [{"text": "📄 Relatório", "callback_data": "report"}, {"text": "⏱ Status", "callback_data": "status"}],
]}


def fmt_summary(report):
    """Resumo curto de um relatório (ou do evento 'done') para o chat."""
    an = report.get("analysis") or {}
    hosts = report.get("hosts") or []
    lvl = an.get("level", "none")
    lines = [f"{LEVEL_ICON.get(lvl, '⚪')} Risco da rede: {str(an.get('label', 'ok')).upper()} ({an.get('risk', 0)}/100)",
             f"🖥 {len(hosts)} aparelho(s) · alvo {report.get('target', '?')}"]
    if report.get("timestamp"):
        lines.append(f"🕒 {report['timestamp']}")
    alerts = report.get("alerts") or []
    if alerts:
        lines.append("")
        lines.append("⚠️ Alertas:")
        lines += [f"• {a['text']}" for a in alerts[:6]]
    top = an.get("top") or []
    if top:
        lines.append("")
        lines.append("🛠 Corrija primeiro:")
        for t in top[:3]:
            lines.append(f"• [{t['score']}] {t['title']} — {t['ip']} porta {t['port']}")
            if t.get("fix"):
                lines.append(f"  ↳ {t['fix']}")
    elif hosts:
        lines.append("")
        lines.append("✅ Nenhum problema relevante encontrado.")
    return "\n".join(lines)


def fmt_host(h):
    """Detalhe de um aparelho (usado no /verificar <IP>)."""
    lines = [f"🖥 {h['ip']} — {h.get('type_label') or 'desconhecido'}"
             + (f" · {h.get('vendor')}" if h.get("vendor") else "")
             + f" · risco {h.get('risk', 0)}/100"]
    ports = h.get("ports") or []
    lines.append("Portas: " + (", ".join(f"{p['port']}/{p['proto']} {p.get('service') or ''}".strip() for p in ports[:15]) or "nenhuma aberta"))
    vulns = h.get("vulns") or []
    for v in vulns[:5]:
        lines.append(f"• [{v.get('severity', 'info').upper()}] {v.get('title') or v.get('id')} (porta {v.get('port')})")
        if v.get("fix"):
            lines.append(f"  ↳ {v['fix']}")
    if not vulns and ports:
        lines.append("✅ Nenhuma vulnerabilidade sinalizada.")
    return "\n".join(lines)


def fmt_devices(hosts):
    if not hosts:
        return "Nenhum aparelho na última varredura."
    rows = sorted(hosts, key=lambda h: -(h.get("risk") or 0))
    lines = [f"🖥 {len(hosts)} aparelho(s) — mais arriscados primeiro:"]
    for h in rows[:40]:
        name = h.get("hostname") or h.get("vendor") or ""
        trust = " ✓" if h.get("trusted") else ""
        lines.append(f"{LEVEL_ICON.get(h.get('risk_level', 'none'), '⚪')} {h['ip']} · {h.get('type_label') or '?'}"
                     f"{' · ' + name if name else ''} · {h.get('risk', 0)}{trust}")
    if len(hosts) > 40:
        lines.append(f"… e mais {len(hosts) - 40}.")
    return "\n".join(lines)


class TelegramBot(threading.Thread):
    """Recebe comandos e cliques nos botões; dispara varreduras pelo Scanner do servidor."""

    def __init__(self, settings_path, data_dir, scanner, scheduler, history, log=print, api=None):
        super().__init__(daemon=True)
        self.settings_path = settings_path
        self.data_dir = data_dir
        self.scanner = scanner
        self.scheduler = scheduler
        self.history = history          # função: lista de relatórios (mais recente primeiro)
        self.log = log
        self.api = api or self._http_api
        self.base = "https://api.telegram.org"
        self.offset = 0
        self.token = None
        self.pending = None             # chat que pediu a varredura em andamento: recebe o resumo
        self.single = False
        self.target_label = ""
        scanner.listeners.append(self.on_scan_message)

    # ---------- Telegram API ----------
    def _http_api(self, method, params=None, files=None, timeout=35):
        url = f"{self.base}/bot{self.token}/{method}"
        if files:
            boundary = uuid.uuid4().hex
            body = b""
            for k, v in (params or {}).items():
                body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
            for k, (fname, data) in files.items():
                body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{fname}\"\r\n"
                         "Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"
            body += f"--{boundary}--\r\n".encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        else:
            data = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in (params or {}).items()}
            req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode())
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)

    def send(self, chat, text, keyboard=None):
        params = {"chat_id": chat, "text": text[:4000]}
        if keyboard:
            params["reply_markup"] = keyboard
        try:
            self.api("sendMessage", params)
        except (OSError, ValueError) as e:
            self.log(f"Telegram: falha ao enviar mensagem — {automation.telegram_error(e)}")

    # ---------- laço principal ----------
    def run(self):
        registered = None
        while True:
            integ = automation.load_settings(self.settings_path)["integrations"]
            token, chat = integ.get("telegram_token"), str(integ.get("telegram_chat") or "")
            # sem chat configurado o bot também roda: responde o id a quem mandar /start
            if not (token and integ.get("telegram_bot", True)):
                time.sleep(15)
                continue
            if token != self.token:
                self.token, self.offset, registered = token, 0, None
            try:
                if registered != token:
                    self.api("setMyCommands", {"commands": [{"command": c, "description": d} for c, d in COMMANDS]})
                    registered = token
                res = self.api("getUpdates", {"offset": self.offset, "timeout": 25,
                                              "allowed_updates": ["message", "callback_query"]})
                for upd in res.get("result", []):
                    self.offset = upd["update_id"] + 1
                    self.handle_update(upd, chat)
            except (OSError, ValueError) as e:
                # token errado, sem internet ou outro processo usando o mesmo bot (409)
                self.log(f"Telegram: {automation.telegram_error(e)}; nova tentativa em 30 s.")
                time.sleep(30)

    def handle_update(self, upd, allowed_chat):
        if "callback_query" in upd:
            cq = upd["callback_query"]
            chat = str(((cq.get("message") or {}).get("chat") or {}).get("id", ""))
            try:
                self.api("answerCallbackQuery", {"callback_query_id": cq["id"]})
            except (OSError, ValueError):
                pass
            if chat != allowed_chat:
                return
            self.on_button(chat, cq.get("data") or "")
            return
        msg = upd.get("message") or {}
        chat = str((msg.get("chat") or {}).get("id", ""))
        if chat != allowed_chat:
            # só o dono do netscan conversa com o bot; a quem não é, mostra o próprio id para
            # facilitar a configuração (não dá acesso a nada)
            if (msg.get("text") or "").strip().split("@")[0] == "/start" and chat:
                self.send(chat, f"🔒 Este bot é privado do netscan.\n\nSeu id de chat é: {chat}\n\n"
                                "Se este netscan é seu, cole esse número em Preferências → Integrações → "
                                "Telegram — id do chat e clique em Enviar notificação de teste.")
            return
        text = (msg.get("text") or "").strip()
        if text.startswith("/"):
            cmd, _, arg = text[1:].partition(" ")
            self.on_command(chat, cmd.split("@")[0].lower(), arg.strip())

    # ---------- comandos ----------
    def on_command(self, chat, cmd, arg):
        if cmd in ("start", "ajuda", "help"):
            self.send(chat, "netscan — comandos:\n" + "\n".join(f"/{c} — {d}" for c, d in COMMANDS), MAIN_KEYBOARD)
        elif cmd in ("verificar", "verificar_completa"):
            self.start_scan(chat, arg, full=cmd == "verificar_completa")
        elif cmd == "status":
            self.send(chat, self.status_text(), MAIN_KEYBOARD)
        elif cmd == "ultimo":
            self.send_last_summary(chat)
        elif cmd == "aparelhos":
            r = self.last_report()
            self.send(chat, fmt_devices((r or {}).get("hosts") or []) if r else "Ainda não há varreduras.")
        elif cmd == "relatorio":
            self.send_report(chat)
        elif cmd in ("pausar", "retomar"):
            self.set_paused(chat, cmd == "pausar")
        else:
            self.send(chat, "Comando desconhecido. Envie /ajuda.")

    def on_button(self, chat, data):
        if data == "scan":
            self.start_scan(chat, "", full=False)
        elif data == "scan_full":
            self.start_scan(chat, "", full=True)
        elif data == "summary":
            self.send_last_summary(chat)
        elif data == "report":
            self.send_report(chat)
        elif data == "status":
            self.send(chat, self.status_text(), MAIN_KEYBOARD)
        elif data.startswith("trust:"):
            self.trust(chat, data[6:])

    def start_scan(self, chat, target, full):
        target = target.strip()
        if target and (not TARGET_RE.match(target) or len(target) > 200):
            self.send(chat, "Alvo inválido. Exemplos: /verificar 192.168.0.10 · /verificar 192.168.0.0/24")
            return
        s = automation.load_settings(self.settings_path)["scan"]
        opts = {"target": target or s["target"], "fast": not full, "ports": s["ports"], "exclude": s["exclude"],
                "workers": s["workers"], "udp": s["udp"], "noPing": s["noPing"], "ipv6": s["ipv6"],
                "defaultCreds": s["defaultCreds"], "compare": "latest"}
        if target:
            # um aparelho só: não entra no histórico nem vira base da comparação da rede inteira
            opts.update(single=True, compare="")
        res = self.scanner.start(opts, origin="telegram")
        if not res.get("ok"):
            self.send(chat, f"⏳ {res.get('error', 'Não foi possível iniciar.')} Use /status.")
            return
        self.pending, self.single = chat, bool(target)
        self.target_label = target or s["target"] or "sub-redes locais"
        kind = "completa" if full else "rápida"
        self.send(chat, f"🔍 Varredura {kind} iniciada em {self.target_label}. "
                        "Aviso quando terminar.")

    def on_scan_message(self, msg):
        """Chamado pelo Scanner a cada evento: manda o resultado para quem pediu pelo Telegram."""
        if not self.pending:
            return
        chat = self.pending
        if msg["type"] == "event" and msg["data"].get("event") == "done":
            evt = msg["data"]
            if self.single and evt.get("hosts"):
                text = "✅ Varredura concluída\n\n" + "\n\n".join(fmt_host(h) for h in evt["hosts"])
            elif self.single:
                text = "Nenhum aparelho respondeu nesse endereço."
            else:
                text = "✅ Varredura concluída\n\n" + fmt_summary({**evt, "target": self.target_label})
            self.pending = None
            self.send(chat, text, MAIN_KEYBOARD)
        elif msg["type"] == "event" and msg["data"].get("event") in ("fatal", "aborted"):
            self.pending = None
            self.send(chat, f"⚠️ Varredura interrompida: {msg['data'].get('error', 'parada manualmente')}")

    def status_text(self):
        sch = self.scheduler.status()
        lines = ["⏳ Varredura em andamento." if self.scanner.running else "💤 Nenhuma varredura em andamento."]
        if sch.get("paused"):
            lines.append(f"⏸ Agendamento pausado (a cada {sch['every']} min). Use /retomar.")
        elif sch.get("every"):
            lines.append(f"⏱ Agendada a cada {sch['every']} min" + (f", próxima às {sch['next']}." if sch.get("next") else "."))
        else:
            lines.append("⏱ Sem varredura agendada (configure em Preferências → Agendamento).")
        hist = self.history()
        if hist:
            lines.append(f"🕒 Última: {hist[0]['timestamp']} · {hist[0]['hosts']} aparelho(s) · risco {hist[0].get('risk', '?')}")
        return "\n".join(lines)

    def last_report(self):
        hist = self.history()
        if not hist:
            return None
        try:
            with open(os.path.join(self.data_dir, hist[0]["name"], "relatorio.json")) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def send_last_summary(self, chat):
        r = self.last_report()
        self.send(chat, fmt_summary(r) if r else "Ainda não há varreduras. Toque em 🔍 Verificar agora.", MAIN_KEYBOARD)

    def send_report(self, chat):
        hist = self.history()
        if not hist:
            self.send(chat, "Ainda não há varreduras.")
            return
        folder = os.path.join(self.data_dir, hist[0]["name"])
        for fname in ("relatorio.pdf", "relatorio.html"):
            path = os.path.join(folder, fname)
            if os.path.isfile(path) and os.path.getsize(path) < 45_000_000:  # limite do Telegram: 50 MB
                with open(path, "rb") as f:
                    data = f.read()
                try:
                    self.api("sendDocument", {"chat_id": chat, "caption": f"Relatório de {hist[0]['timestamp']}"
                                              + (" — abra no navegador" if fname.endswith(".html") else "")},
                             files={"document": (f"netscan-{hist[0]['name']}{os.path.splitext(fname)[1]}", data)})
                except (OSError, ValueError) as e:
                    self.send(chat, f"Não consegui enviar o relatório: {automation.telegram_error(e)}.")
                return
        self.send(chat, "O relatório da última varredura não foi encontrado.")

    def set_paused(self, chat, paused):
        s = automation.load_settings(self.settings_path)
        if not s["schedule"]["every"]:
            self.send(chat, "Não há varredura agendada. Configure em Preferências → Agendamento.")
            return
        automation.save_settings({"schedule": {"paused": paused}}, self.settings_path)
        self.scheduler.next_run = None
        self.send(chat, "⏸ Agendamento pausado. Use /retomar para voltar." if paused
                  else f"▶️ Agendamento retomado: a cada {s['schedule']['every']} min.")

    def trust(self, chat, key):
        if not KEY_RE.match(key):
            return
        path = os.path.join(self.data_dir, automation.INVENTORY_FILE)
        inv = automation.load_inventory(path)
        if key not in inv:
            self.send(chat, "Esse aparelho não está mais no inventário.")
            return
        inv[key]["trusted"] = True
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(inv, f, indent=1, ensure_ascii=False)
        os.replace(tmp, path)
        d = inv[key]
        self.send(chat, f"✅ {d.get('ips', ['?'])[-1]} ({d.get('type_label') or d.get('vendor') or key}) marcado como confiável. "
                        "Não vai mais gerar alerta de aparelho desconhecido.")
