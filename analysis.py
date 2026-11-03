"""netscan — análise automática dos resultados.

- Inteligência de ameaças: CISA KEV (CVEs explorados ativamente) e EPSS (probabilidade de
  exploração), baixados uma vez e guardados em cache para uso offline.
- Confiança de cada achado, nota de risco (0-100) por achado, por dispositivo e da rede.
- Tipo provável de cada dispositivo e regras de risco por tipo.
- Resumo em português e lista "corrija primeiro".
"""
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "netscan")
UA = {"User-Agent": "netscan"}
KEV_MAX_AGE = 86400          # 1 dia
EPSS_MAX_AGE = 7 * 86400     # 7 dias

SEV_BASE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
CONF_MULT = {"high": 1.0, "medium": 0.85, "low": 0.6}
LEVELS = [(80, "critical", "crítico"), (60, "high", "alto"), (35, "medium", "médio"), (1, "low", "baixo")]

TYPE_LABELS = {
    "router": "roteador", "printer": "impressora", "camera": "câmera", "nas": "NAS",
    "tv": "TV / mídia", "iot": "IoT", "windows": "computador Windows", "phone": "celular / tablet",
    "linux": "Linux / servidor", "mac": "Mac", "unknown": "desconhecido",
}
EXPOSED_TYPES = {"camera", "iot", "router", "printer", "nas", "tv"}  # raramente atualizados


def _fetch_json(url, timeout=20):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)  # escrita atômica: cache nunca fica pela metade


class Intel:
    """KEV + EPSS com cache local. Falha de rede nunca interrompe a varredura."""

    def __init__(self, offline=False, log=None, cache_dir=CACHE_DIR):
        self.offline = offline
        self.log = log or (lambda msg, level="*": None)
        self.cache_dir = cache_dir
        self.lock = threading.Lock()
        self.kev = {}
        self.epss = {}  # cve -> [score, ts]
        self._load_kev()
        self._load_epss()

    def _load_kev(self):
        path = os.path.join(self.cache_dir, "kev.json")
        fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < KEV_MAX_AGE
        if not fresh and not self.offline:
            try:
                _write_json(path, _fetch_json(KEV_URL))
            except (OSError, ValueError) as e:
                self.log(f"Catálogo CISA KEV indisponível ({e}); usando cache se houver.", "~")
        try:
            with open(path) as f:
                data = json.load(f)
            self.kev = {v["cveID"].upper(): {
                "name": v.get("vulnerabilityName"),
                "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            } for v in data.get("vulnerabilities", [])}
            self.log(f"CISA KEV: {len(self.kev)} CVEs explorados ativamente carregados.")
        except (OSError, ValueError, KeyError, AttributeError, TypeError):
            self.kev = {}

    def _load_epss(self):
        try:
            with open(os.path.join(self.cache_dir, "epss.json")) as f:
                self.epss = json.load(f)
        except (OSError, ValueError):
            self.epss = {}

    def lookup_epss(self, cves):
        now = time.time()
        with self.lock:
            missing = sorted({c for c in cves if c not in self.epss or now - self.epss[c][1] > EPSS_MAX_AGE})
        if missing and not self.offline:
            got = {}
            try:
                for i in range(0, len(missing), 100):  # a API aceita até 100 CVEs por chamada
                    batch = missing[i:i + 100]
                    data = _fetch_json(EPSS_URL + "?" + urllib.parse.urlencode({"cve": ",".join(batch)}))
                    for row in data.get("data", []):
                        got[row["cve"].upper()] = float(row["epss"])
                    for c in batch:
                        got.setdefault(c, 0.0)  # sem EPSS publicado: trata como 0
            except (OSError, ValueError, KeyError, TypeError) as e:
                self.log(f"EPSS indisponível ({e}).", "~")
            if got:
                with self.lock:
                    for c, s in got.items():
                        self.epss[c] = [s, now]
                    try:
                        _write_json(os.path.join(self.cache_dir, "epss.json"), self.epss)
                    except OSError:
                        pass
        with self.lock:
            return {c: self.epss[c][0] for c in cves if c in self.epss}

    def enrich(self, vulns):
        """Marca em cada achado os CVEs do KEV e o maior EPSS."""
        cves = {c.upper() for v in vulns for c in v.get("cves", [])}
        epss = self.lookup_epss(cves) if cves else {}
        for v in vulns:
            vc = [c.upper() for c in v.get("cves", [])]
            v["kev"] = [c for c in vc if c in self.kev]
            v["ransomware"] = any(self.kev[c]["ransomware"] for c in v["kev"])
            scores = [epss[c] for c in vc if c in epss]
            v["epss"] = round(max(scores), 4) if scores else None


def confidence(v):
    """Quão certo é o achado: observado direto > script confirma > deduzido da versão."""
    if v.get("title"):  # achados próprios (configuração, serviço inseguro, porta só IPv6)
        return "high"
    low = (v.get("output") or "").lower()
    if "likely vulnerable" in low:
        return "medium"
    if "state: vulnerable" in low or "state: exploitable" in low:
        return "high"
    if v.get("id") == "vulners":
        return "medium"  # deduzido da versão: o fornecedor pode ter corrigido sem mudar a versão
    return "medium"


def score_vuln(v, has_exploit=False):
    """Nota 0-100 e os motivos, para ordenar o que corrigir primeiro."""
    base = v.get("cvss") or SEV_BASE.get(v.get("severity", "info"), 0.5)
    s = base * 8
    reasons = []
    if v.get("kev"):
        s += 15
        reasons.append("explorada ativamente (CISA KEV)" + (" · usada por ransomware" if v.get("ransomware") else ""))
    if v.get("epss"):
        s += 10 * v["epss"]
        if v["epss"] >= 0.1:
            reasons.append(f"EPSS {round(v['epss'] * 100)}% de chance de exploração")
    if has_exploit:
        s += 5
        reasons.append("exploit público disponível")
    if v.get("cvss"):
        reasons.insert(0, f"CVSS {v['cvss']}")
    s *= CONF_MULT.get(v.get("confidence", "medium"), 0.85)
    return max(0, min(100, round(s))), reasons


def level(score):
    for lim, key, label in LEVELS:
        if score >= lim:
            return key, label
    return "none", "ok"


def is_random_mac(mac):
    """MAC localmente administrado (bit 0x02): celulares modernos usam MAC aleatório."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, AttributeError, IndexError):
        return False


def device_type(h, gateway=None):
    """Tipo provável do aparelho a partir de portas, serviços, fabricante, SO e nome."""
    ports = {int(p["port"]) for p in h.get("ports", []) if str(p.get("port", "")).isdigit()}
    svcs = " ".join(f"{p.get('service') or ''} {p.get('product') or ''}" for p in h.get("ports", [])).lower()
    vendor = (h.get("vendor") or "").lower()
    osn = ((h.get("os") or {}).get("name") or "").lower()
    name = (h.get("hostname") or "").lower()
    text = f"{svcs} {vendor} {osn} {name}"
    if gateway and h.get("ip") == gateway:
        return "router"
    if ports & {631, 9100, 515} or re.search(r"printer|jetdirect|\bipp\b", svcs + osn):
        return "printer"
    if 554 in ports or "rtsp" in svcs or re.search(r"hikvision|dahua|axis comm|reolink|amcrest|foscam|uniview|ezviz", vendor):
        return "camera"
    if re.search(r"synology|qnap|western digital|buffalo|asustor", text):
        return "nas"
    if ports & {8008, 8009, 7000, 8001, 8002, 9080} or re.search(r"roku|chromecast|sonos|vizio|hisense|\btv\b|smart.?tv|bravia|webos|tizen", text):
        return "tv"
    if ports & {1883, 8883} or re.search(r"espressif|tuya|shelly|sonoff|itead|amazon tech|google|ring\b|wiz\b|philips light", vendor):
        return "iot"
    if re.search(r"router|gateway|mikrotik|ubiquiti|routeros|openwrt|dd-wrt", text) or (53 in ports and ports & {80, 443}):
        return "router"
    if ports & {445, 139, 3389, 135} or "windows" in osn:
        return "windows"
    if 62078 in ports or re.search(r"iphone|ipad|android|galaxy|redmi|pixel|moto", name):
        return "phone"
    if "mac os" in osn or "macos" in osn or (ports & {548, 5900} and "apple" in vendor):
        return "mac"
    if not ports and (is_random_mac(h.get("mac")) or re.search(r"apple|samsung|xiaomi|motorola|oneplus|huawei|oppo|vivo|realme", vendor)):
        return "phone"
    if "linux" in osn or 22 in ports:
        return "linux"
    return "unknown"


def apply_type_rules(t, vulns):
    """Regras por tipo: em câmera/IoT/roteador, serviço sem criptografia é porta de entrada de botnets."""
    for v in vulns:
        if t in EXPOSED_TYPES and v.get("id") == "insecure-service" and v.get("severity") in ("low", "medium"):
            v["severity"] = "high"
            v.setdefault("notes", []).append(
                f"Em {TYPE_LABELS[t]} isso é alvo comum de botnets (ex.: Mirai), que entram por Telnet/FTP com senha padrão.")


def analyze_host(h, intel=None, gateway=None):
    """Enriquece os achados do host e calcula tipo e risco. Altera h no lugar."""
    t = device_type(h, gateway)
    h["type"], h["type_label"] = t, TYPE_LABELS[t]
    vulns = h.get("vulns", [])
    if intel is not None:
        intel.enrich(vulns)
    apply_type_rules(t, vulns)
    expl_ports = {p["port"] for p in h.get("ports", []) if p.get("exploits")}
    for v in vulns:
        v["confidence"] = confidence(v)
        v["score"], v["reasons"] = score_vuln(v, v.get("port") in expl_ports)
    vulns.sort(key=lambda v: -v["score"])
    counts = {s: 0 for s in SEV_BASE}
    for v in vulns:
        counts[v.get("severity", "info")] = counts.get(v.get("severity", "info"), 0) + 1
    h["severity"] = counts
    relevant = [v for v in vulns if v["score"] >= 35]
    risk = (vulns[0]["score"] if vulns else 0) + min(10, 2 * max(0, len(relevant) - 1))
    if expl_ports and risk < 30:
        risk = 30  # versão exposta com exploit público, mesmo sem achado confirmado
    h["risk"] = min(100, risk)
    h["risk_level"], h["risk_label"] = level(h["risk"])
    return h


def finding_title(h, v):
    """Título legível: 'vulners' vira 'Versão vulnerável de <produto> (N CVEs)'."""
    if v.get("title"):
        return v["title"]
    if v.get("id") == "vulners":
        p = next((p for p in h.get("ports", []) if p.get("port") == v.get("port")), {})
        prod = " ".join(filter(None, [p.get("product"), p.get("version")])) or p.get("service") or "serviço"
        return f"Versão vulnerável de {prod} ({len(v.get('cves', []))} CVEs)"
    return v.get("id") or "achado"


def analyze_network(hosts, diff=None):
    """Nota da rede, resumo em português e top 5 para corrigir primeiro."""
    all_v = [(h, v) for h in hosts for v in h.get("vulns", [])]
    all_v.sort(key=lambda hv: -hv[1].get("score", 0))
    top = [{
        "ip": h["ip"], "type": h.get("type_label"), "port": v.get("port"), "id": v.get("id"),
        "title": finding_title(h, v), "severity": v.get("severity"), "score": v.get("score", 0),
        "reasons": v.get("reasons", []), "fix": v.get("fix"),
    } for h, v in all_v if v.get("score", 0) >= 20][:5]
    risk = max((h.get("risk", 0) for h in hosts), default=0)
    lvl, label = level(risk)

    summary = []
    flagged = [h for h in hosts if h.get("risk", 0) >= 35]
    summary.append(f"{len(hosts)} dispositivo(s) na rede; {len(flagged)} com algo importante a corrigir.")
    summary.append(f"Risco geral: {label.upper()} ({risk}/100).")
    urgent = [h for h in hosts if h.get("risk", 0) >= 60]
    if urgent:
        summary.append("Precisam de atenção agora: " + ", ".join(
            f"{h['ip']} ({h.get('type_label', '?')})" for h in urgent[:6]) + ".")
    kev = sorted({c for _, v in all_v for c in v.get("kev", [])})
    if kev:
        summary.append(f"{len(kev)} falha(s) já são exploradas por atacantes de verdade (CISA KEV): {', '.join(kev[:5])}.")
    insecure = [f"{h['ip']}:{v['port']}" for h, v in all_v if v.get("id") == "insecure-service"]
    if insecure:
        summary.append(f"Serviços sem criptografia expostos em {', '.join(insecure[:6])}.")
    v6 = [h["ip"] for h, v in all_v if v.get("id") == "ipv6-only-port"]
    if v6:
        summary.append(f"Portas abertas só via IPv6 (firewall incompleto) em {', '.join(sorted(set(v6)))}.")
    if diff and diff.get("new_hosts"):
        summary.append(f"Dispositivo(s) novo(s) desde a última varredura: {', '.join(diff['new_hosts'][:6])}.")
    types = {}
    for h in hosts:
        types[h.get("type_label", "desconhecido")] = types.get(h.get("type_label", "desconhecido"), 0) + 1
    if types:
        summary.append("Na rede: " + ", ".join(f"{n} {t}" for t, n in sorted(types.items(), key=lambda x: -x[1])) + ".")
    if not top:
        summary.append("Nenhum problema relevante encontrado. Mantenha os aparelhos atualizados e repita a varredura de tempos em tempos.")
    return {"risk": risk, "level": lvl, "label": label, "summary": summary, "top": top, "types": types}
