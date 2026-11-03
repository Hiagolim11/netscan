"""netscan — automação: inventário de dispositivos, alertas, notificações e serviço do systemd.

Notificações são configuradas por variáveis de ambiente (nunca na linha de comando, que
aparece no `ps`). No serviço, elas ficam em /etc/netscan.env (modo 600):
  NETSCAN_WEBHOOK=https://ntfy.sh/meu-topico      (ntfy, Discord ou Slack)
  NETSCAN_TELEGRAM_TOKEN=123:ABC  NETSCAN_TELEGRAM_CHAT=456
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime

INVENTORY_FILE = "inventario.json"
HISTORY_PER_DEVICE = 30
# portas cuja abertura nova merece alerta (acesso remoto, bancos, compartilhamento, texto puro)
RISKY_PORTS = {21, 23, 135, 139, 445, 512, 513, 514, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017, 161}

SERVICE_NAME = "netscan"
UNIT_DIR = "/etc/systemd/system"
STATE_DIR = "/var/lib/netscan"
ENV_FILE = "/etc/netscan.env"


# ---------------- inventário ----------------

def device_key(h):
    """Identidade estável do aparelho: MAC (o IP muda com DHCP); sem MAC, o IP."""
    return (h.get("mac") or h["ip"]).upper()


def load_inventory(path=INVENTORY_FILE):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def update_inventory(hosts, path=INVENTORY_FILE, now=None):
    """Registra quem foi visto. Devolve (chaves novas, se é a primeira varredura)."""
    inv = load_inventory(path)
    baseline = not inv  # primeira vez: tudo é novo, mas não é "intruso"
    now = now or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new = []
    for h in hosts:
        k = device_key(h)
        d = inv.get(k)
        if d is None:
            new.append(k)
            d = inv[k] = {"first_seen": now, "seen": 0, "trusted": False, "ips": [], "history": []}
        d["last_seen"] = now
        d["seen"] = d.get("seen", 0) + 1
        for field in ("vendor", "hostname", "type_label"):
            if h.get(field):
                d[field] = h[field]
        if h["ip"] not in d["ips"]:
            d["ips"] = (d["ips"] + [h["ip"]])[-10:]
        d["history"] = (d.get("history", []) + [[now, h["ip"], h.get("risk", 0), len(h.get("ports", []))]])[-HISTORY_PER_DEVICE:]
        h["inv_key"], h["first_seen"], h["seen_count"], h["trusted"] = k, d["first_seen"], d["seen"], d.get("trusted", False)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(inv, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)
    return new, baseline


# ---------------- alertas ----------------

def build_alerts(hosts, diff=None, new_keys=(), baseline=False):
    """Mudanças que merecem aviso, mais graves primeiro."""
    alerts = []
    for h in hosts:
        if not baseline and h.get("inv_key") in new_keys and not h.get("trusted"):
            what = h.get("type_label") or "aparelho"
            who = h.get("vendor") or h.get("hostname") or "fabricante desconhecido"
            alerts.append({"level": "high", "ip": h["ip"],
                           "text": f"Dispositivo nunca visto na rede: {h['ip']} ({what}, {who})."})
    changed = (diff or {}).get("changed", {})
    for ip, d in changed.items():
        risky = [p for p in d.get("new_ports", []) if p.split("/")[0].isdigit() and int(p.split("/")[0]) in RISKY_PORTS]
        if risky:
            alerts.append({"level": "medium", "ip": ip, "text": f"{ip} abriu porta sensível: {', '.join(risky)}."})
    # vulnerabilidade nova (ou todas, na primeira comparação) que seja grave ou explorada ativamente
    for h in hosts:
        new_v = set(changed.get(h["ip"], {}).get("new_vulns", []))
        is_new_host = diff is None or h["ip"] in (diff or {}).get("new_hosts", [])
        for v in h.get("vulns", []):
            key = f"{v.get('port')}:{v.get('id')}"
            if not (is_new_host or key in new_v):
                continue
            if v.get("kev"):
                alerts.append({"level": "critical", "ip": h["ip"],
                               "text": f"{h['ip']}: falha explorada ativamente ({', '.join(v['kev'][:3])}) na porta {v.get('port')}."})
            elif v.get("severity") in ("critical", "high"):
                title = v.get("title") or v.get("id")
                alerts.append({"level": v["severity"], "ip": h["ip"], "text": f"{h['ip']}: {title} (porta {v.get('port')})."})
            elif v.get("id") == "ssl-cert":
                alerts.append({"level": "low", "ip": h["ip"], "text": f"{h['ip']}: {v.get('title')}."})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: order.get(a["level"], 9))
    return alerts


# ---------------- notificações ----------------

def _post(url, body, content_type):
    req = urllib.request.Request(url, data=body, headers={"Content-Type": content_type, "User-Agent": "netscan"})
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read()


def notify(alerts, summary_line="", log=None):
    """Envia os alertas pelos canais configurados no ambiente. Falha de envio só é registrada."""
    log = log or (lambda msg, level="*": None)
    if not alerts:
        return []
    text = "netscan — " + (summary_line or f"{len(alerts)} alerta(s)") + "\n" + "\n".join(
        f"• [{a['level'].upper()}] {a['text']}" for a in alerts[:15])
    sent = []
    hook = os.environ.get("NETSCAN_WEBHOOK")
    if hook:
        try:
            if "ntfy" in hook:  # ntfy mostra o corpo como texto puro
                _post(hook, text.encode(), "text/plain; charset=utf-8")
            else:  # Discord lê "content", Slack lê "text"
                _post(hook, json.dumps({"content": text[:1900], "text": text}).encode(), "application/json")
            sent.append("webhook")
        except (OSError, ValueError) as e:
            log(f"Falha ao enviar webhook: {e}", "~")
    token, chat = os.environ.get("NETSCAN_TELEGRAM_TOKEN"), os.environ.get("NETSCAN_TELEGRAM_CHAT")
    if token and chat:
        try:
            url = f"https://api.telegram.org/bot{urllib.parse.quote(token, safe=':')}/sendMessage"
            _post(url, urllib.parse.urlencode({"chat_id": chat, "text": text[:4000]}).encode(),
                  "application/x-www-form-urlencoded")
            sent.append("telegram")
        except (OSError, ValueError) as e:
            log(f"Falha ao enviar Telegram: {type(e).__name__}", "~")  # sem a URL: ela contém o token
    if shutil.which("notify-send") and os.environ.get("DISPLAY") and os.geteuid() != 0:
        try:
            subprocess.run(["notify-send", "-a", "netscan", "netscan", text[:500]], timeout=5, check=False)
            sent.append("desktop")
        except (OSError, subprocess.SubprocessError):
            pass
    return sent


# ---------------- serviço do systemd ----------------

def service_units(script, every_min, scan_args, python=None):
    """Conteúdo do .service e do .timer."""
    python = python or sys.executable or "/usr/bin/python3"
    cmd = " ".join(shlex.quote(x) for x in [python, script, "--compare", "latest", "--notify", "--keep", "100"] + scan_args)
    service = f"""[Unit]
Description=netscan — varredura periódica da rede
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
StateDirectory={SERVICE_NAME}
WorkingDirectory={STATE_DIR}
EnvironmentFile=-{ENV_FILE}
ExecStart={cmd}
Nice=10
TimeoutStartSec=6h
"""
    timer = f"""[Unit]
Description=Agenda o netscan a cada {every_min} min

[Timer]
OnBootSec=5min
OnUnitActiveSec={every_min}min
Persistent=true

[Install]
WantedBy=timers.target
"""
    return service, timer


def install_service(script, every_min, scan_args, log=None):
    log = log or (lambda msg, level="*": None)
    if os.geteuid() != 0:
        raise PermissionError("instalar o serviço exige root (use sudo)")
    if not 5 <= every_min <= 10080:
        raise ValueError("intervalo deve ficar entre 5 min e 7 dias")
    service, timer = service_units(os.path.abspath(script), every_min, scan_args)
    with open(os.path.join(UNIT_DIR, f"{SERVICE_NAME}.service"), "w") as f:
        f.write(service)
    with open(os.path.join(UNIT_DIR, f"{SERVICE_NAME}.timer"), "w") as f:
        f.write(timer)
    if not os.path.exists(ENV_FILE):
        fd = os.open(ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("# Notificações do netscan (descomente e preencha)\n"
                    "#NETSCAN_WEBHOOK=https://ntfy.sh/seu-topico\n"
                    "#NETSCAN_TELEGRAM_TOKEN=\n#NETSCAN_TELEGRAM_CHAT=\n")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", f"{SERVICE_NAME}.timer"], check=True)
    log(f"Serviço instalado: varredura a cada {every_min} min, resultados em {STATE_DIR}.", "+")


def uninstall_service(log=None):
    log = log or (lambda msg, level="*": None)
    if os.geteuid() != 0:
        raise PermissionError("remover o serviço exige root (use sudo)")
    subprocess.run(["systemctl", "disable", "--now", f"{SERVICE_NAME}.timer"], check=False)
    for unit in (f"{SERVICE_NAME}.service", f"{SERVICE_NAME}.timer"):
        try:
            os.remove(os.path.join(UNIT_DIR, unit))
        except FileNotFoundError:
            pass
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    log(f"Serviço removido (resultados e {ENV_FILE} foram mantidos).", "+")


def prune_results(base_dir, keep):
    """Mantém só as `keep` varreduras mais recentes (o serviço roda para sempre)."""
    dirs = sorted(d for d in os.listdir(base_dir) if d.startswith("resultados_"))
    removed = 0
    for d in dirs[:-keep] if keep > 0 else []:
        shutil.rmtree(os.path.join(base_dir, d), ignore_errors=True)
        removed += 1
    return removed


def latest_report(base_dir="."):
    """relatorio.json da varredura mais recente (para --compare latest)."""
    for d in sorted((d for d in os.listdir(base_dir) if d.startswith("resultados_")), reverse=True):
        f = os.path.join(base_dir, d, "relatorio.json")
        if os.path.exists(f):
            return f
    return None
