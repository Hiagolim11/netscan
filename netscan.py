#!/usr/bin/env python3
"""
netscan — Varredura de rede com descoberta de dispositivos e checagem de vulnerabilidades.

Uso autorizado apenas: execute somente em redes que você possui ou tem permissão
explícita para testar. Ferramenta baseada em nmap.

Fluxo:
  1. Descobre hosts ativos na rede (ping/ARP scan).
  2. Para cada host vivo, detecta portas/serviços, o sistema operacional e roda os
     scripts de vulnerabilidade do nmap (categoria "vuln" + "vulners" para CVEs por
     versão de serviço). Classifica cada achado por severidade (CVSS).
  3. Gera um relatório em texto e JSON com resumo por severidade.

Exemplos:
  sudo python3 netscan.py                      # auto-detecta a sub-rede local
  sudo python3 netscan.py -t 192.168.0.0/24    # alvo explícito
  sudo python3 netscan.py -t 192.168.0.10      # um único host
  sudo python3 netscan.py --fast               # só descoberta + serviços
  sudo python3 netscan.py --deep               # todas as portas + scripts extras
  sudo python3 netscan.py -p 22,80,443 --udp   # portas escolhidas + top 50 UDP
  sudo python3 netscan.py -w 4 --compare resultados_X/relatorio.json   # paralelo + diff
"""

import argparse
import csv
import html
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import analysis
import automation


JSON_STREAM = False
CURRENT_PROCS = set()  # processos nmap em execução (para encerramento limpo)
PROC_LOCK = threading.Lock()
EMIT_LOCK = threading.Lock()
STOPPING = threading.Event()

UDP_TOP = "53,67,68,69,123,137,138,161,162,500,514,520,1900,4500,5353"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TARGET_RE = re.compile(r"^[A-Za-z0-9.\-/,: ]+$")  # IP, CIDR, range, hostname
STATS_RE = re.compile(r"^(.*?) Timing: About ([\d.]+)% done(?:.*?\((\S+) remaining\))?")
PORTS_RE = re.compile(r"^[0-9TU:,\-]+$")  # sintaxe do -p do nmap


def log(msg, level="*"):
    if JSON_STREAM:
        # mantém stdout limpo para o fluxo JSON; logs vão para stderr
        print(f"[{level}] {msg}", file=sys.stderr, flush=True)
        return
    colors = {"*": "\033[94m", "+": "\033[92m", "!": "\033[91m", "~": "\033[93m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    print(f"{c}[{level}]{reset} {msg}")


def emit(event, **data):
    """Emite um evento JSON por linha no stdout (modo --json-stream)."""
    if JSON_STREAM:
        line = json.dumps({"event": event, **data}, ensure_ascii=False)
        with EMIT_LOCK:  # hosts em paralelo: evita linhas JSON intercaladas
            print(line, flush=True)


def _terminate(signum, frame):
    """Encerra os nmap filhos antes de sair (robustez ao parar a varredura)."""
    STOPPING.set()  # hosts ainda na fila não iniciam novo nmap
    with PROC_LOCK:
        procs = list(CURRENT_PROCS)
    for proc in procs:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    log("Varredura interrompida.", "!")
    emit("aborted")
    sys.exit(130)


def check_prereqs():
    if not shutil.which("nmap"):
        log("nmap não encontrado. Instale com: sudo apt install nmap", "!")
        emit("fatal", error="nmap não encontrado. Instale com: sudo apt install nmap")
        sys.exit(1)


def validate_target(target):
    """Rejeita entradas malformadas; devolve o alvo limpo ou None."""
    if not target:
        return None
    target = target.strip()
    if not TARGET_RE.match(target):
        return None
    return target


def split_targets(target):
    """'a, b c' -> ['a', 'b', 'c'] (o nmap espera cada alvo como argumento próprio)."""
    return [t for t in re.split(r"[\s,]+", target or "") if t]


def detect_local_subnets():
    """Retorna sub-redes IPv4 privadas conectadas, exceto loopback/docker /32."""
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr", "show"], text=True)
    except Exception as e:
        log(f"Não consegui ler interfaces: {e}", "!")
        return []
    subnets = []
    for line in out.splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not m:
            continue
        try:
            net = ipaddress.ip_network(m.group(1), strict=False)
        except ValueError:
            continue
        if net.is_loopback or net.prefixlen == 32:
            continue
        if "docker" in line or re.search(r"\b(br-|veth)", line):
            continue
        if net.is_private:
            subnets.append(str(net))
    return subnets


def detect_gateway():
    """IP do gateway padrão (para reconhecer o roteador)."""
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
    except Exception:
        return None
    m = re.search(r"default via (\S+)", out)
    return m.group(1) if m else None


def run_nmap(args, label, on_progress=None):
    """Roda o nmap, rastreando o processo para encerramento limpo.
    Retorna True se o nmap terminou com código 0. Mesmo em falha parcial,
    o XML gerado ainda é lido pelo chamador.
    on_progress(fase, pct, restante) recebe as linhas de --stats-every (modo JSON)."""
    if STOPPING.is_set():
        return False
    log(f"Executando: nmap {' '.join(args)}", "~")
    stdout = subprocess.PIPE if JSON_STREAM else None
    stderr = subprocess.DEVNULL if JSON_STREAM else None
    try:
        proc = subprocess.Popen(["nmap"] + args, stdout=stdout, stderr=stderr,
                                text=True, errors="replace")
    except FileNotFoundError:
        log("nmap não encontrado durante a execução.", "!")
        return False
    except Exception as e:
        log(f"Falha ao iniciar nmap ({label}): {e}", "!")
        return False
    with PROC_LOCK:
        CURRENT_PROCS.add(proc)
    rc = None
    try:
        if proc.stdout:  # sempre drena o pipe, senão o nmap trava com o buffer cheio
            for line in proc.stdout:
                m = STATS_RE.search(line.strip())
                if m and on_progress:
                    on_progress(m.group(1), float(m.group(2)), m.group(3))
        rc = proc.wait()
    except KeyboardInterrupt:
        _terminate(signal.SIGINT, None)
    finally:
        with PROC_LOCK:
            CURRENT_PROCS.discard(proc)
    if rc != 0:
        log(f"nmap retornou código {rc} ({label}) — usando resultado parcial se houver.", "~")
    return rc == 0


def _parse_discovery(xml_path, no_ping=False):
    """Lê o XML de descoberta; cada host vira {ip (v4 ou v6), mac, vendor, hostname}."""
    if not os.path.exists(xml_path):
        return []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        log(f"Erro ao ler XML de descoberta: {e}", "!")
        return []
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if not no_ping and status is not None and status.get("state") != "up":
            continue
        ip = ip6 = mac = vendor = name = None
        for addr in host.findall("address"):
            t = addr.get("addrtype")
            if t == "ipv4":
                ip = addr.get("addr")
            elif t == "ipv6":
                ip6 = addr.get("addr")
            elif t == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        hn = host.find("hostnames/hostname")
        if hn is not None:
            name = hn.get("name")
        if ip or ip6:
            hosts.append({"ip": ip or ip6, "mac": mac, "vendor": vendor, "hostname": name})
    return hosts


def ipv6_ifaces():
    """Interfaces com IPv6 link-local onde faz sentido multicast (sem VPN/docker)."""
    try:
        out = subprocess.check_output(["ip", "-6", "-o", "addr", "show", "scope", "link"], text=True)
    except Exception:
        return []
    names = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[1].split("@")[0]
        if re.match(r"^(lo|docker|br-|veth|tailscale|tun|wg|virbr)", name) or name in names:
            continue
        names.append(name)
    return names


def merge_ipv6(hosts, found, iface):
    """Junta os vizinhos IPv6 aos hosts IPv4 pelo MAC; os sem par viram hosts próprios."""
    by_mac = {h["mac"].upper(): h for h in hosts if h.get("mac")}
    known = {h["ip"] for h in hosts}
    for f in found:
        addr = f["ip"]
        if addr.lower().startswith("fe80") and "%" not in addr:
            addr += "%" + iface  # link-local só é alcançável indicando a interface
        twin = by_mac.get((f.get("mac") or "").upper())
        if twin is not None and twin["ip"] != addr:
            if addr not in twin.setdefault("ipv6", []):
                twin["ipv6"].append(addr)
        elif addr not in known:
            hosts.append({**f, "ip": addr})
            known.add(addr)
    return hosts


def discover_hosts(target, outdir, exclude=None, no_ping=False, ipv6=False):
    """Ping/ARP scan para descobrir hosts ativos (ou -Pn: lista todos os alvos).
    ipv6=True também acha vizinhos IPv6 por multicast (ff02::1) em cada interface."""
    log(f"Descobrindo dispositivos em {target} ...")
    targets = split_targets(target)
    excl = split_targets(exclude)
    hosts = []
    # o nmap não mistura IPv4 e IPv6 numa mesma execução
    for fam, tg in (("4", [t for t in targets if ":" not in t]), ("6", [t for t in targets if ":" in t])):
        if not tg:
            continue
        xml_path = os.path.join(outdir, "discovery.xml" if fam == "4" else "discovery6.xml")
        args = ["-sL", "-n"] if no_ping else (["-sn", "-PR"] if fam == "4" else ["-sn"])
        if fam == "6":
            args = ["-6"] + args
        ex = [x for x in excl if (":" in x) == (fam == "6")]
        if ex:
            args += ["--exclude", ",".join(ex)]
        run_nmap(args + ["-oX", xml_path] + tg, f"descoberta IPv{fam}")
        hosts += _parse_discovery(xml_path, no_ping)
    if ipv6:
        for iface in ipv6_ifaces():
            log(f"Procurando vizinhos IPv6 em {iface} ...")
            xml_path = os.path.join(outdir, f"discovery6_{iface}.xml")
            run_nmap(["-6", "-sn", "--script", "targets-ipv6-multicast-echo",
                      "--script-args", f"newtargets,interface={iface}", "-oX", xml_path],
                     f"descoberta IPv6 {iface}")
            found = [f for f in _parse_discovery(xml_path) if f["ip"] not in excl]
            merge_ipv6(hosts, found, iface)
    return hosts


def _safe_name(ip):
    return re.sub(r"[^A-Za-z0-9]", "_", ip)


def _port_spec(ports):
    """Lista de portas abertas -> sintaxe -p do nmap (T:..,U:..)."""
    tcp = sorted({int(p["port"]) for p in ports if p.get("proto") == "tcp"})
    udp = sorted({int(p["port"]) for p in ports if p.get("proto") == "udp"})
    parts = []
    if tcp:
        parts.append("T:" + ",".join(map(str, tcp)))
    if udp:
        parts.append("U:" + ",".join(map(str, udp)))
    return ",".join(parts), bool(udp)


def scan_host(ip, outdir, fast=False, deep=False, is_root=False,
              ports=None, udp=False, no_ping=False, timeout=1200, ipv6_addrs=None,
              default_creds=False):
    """Fase 1: portas, serviços e SO. Fase 2 (se não fast): só nas portas abertas, com os
    scripts escolhidos para cada serviço encontrado (varredura adaptativa).
    ipv6_addrs: endereços IPv6 do mesmo aparelho, conferidos atrás de portas só-IPv6."""
    base = ["-T4", "--host-timeout", f"{timeout}s"]
    if ":" in ip:
        base.append("-6")
    if no_ping:
        base.append("-Pn")
    if JSON_STREAM:
        base += ["--stats-every", "5s"]
    progress = lambda phase, pct, eta: emit("host_progress", ip=ip, phase=phase, pct=pct, eta=eta)

    xml1 = os.path.join(outdir, f"host_{_safe_name(ip)}.xml")
    args = ["-sV", "-oX", xml1] + base
    if is_root:
        args.append("-O")  # detecção de SO exige root
    if udp and is_root:
        # -sS explícito: com -sU o nmap não faria TCP por padrão
        args += ["-sS", "-sU"]
        if not ports:
            # shortcut: TCP 1-1000 em vez do "top 1000" (não combinável com UDP por protocolo)
            ports = ("T:1-65535" if deep else "T:1-1000") + ",U:" + UDP_TOP
    if ports:
        args += ["-p", ports]
    elif deep:
        args.append("-p-")  # todas as 65535 portas
    run_nmap(args + [ip], f"serviços {ip}", progress)
    result = parse_host_scan(xml1, ip)

    if not fast and result["ports"] and not STOPPING.is_set():
        scripts = select_scripts(result["ports"], deep, default_creds)
        spec, has_udp = _port_spec(result["ports"])
        emit("host_progress", ip=ip, phase=f"{len(scripts)} checagens", pct=0, eta=None)
        log(f"{ip}: checagens escolhidas pelos serviços: {', '.join(scripts)}", "~")
        xml2 = os.path.join(outdir, f"host_{_safe_name(ip)}_scripts.xml")
        # sem limite, scripts como http-slowloris-check seguram um host por muitos minutos
        args = ["-sV", "-p", spec, "-oX", xml2, "--script", ",".join(scripts),
                "--script-args", "mincvss=0.0", "--script-timeout", "300s" if deep else "120s"] + base
        if has_udp and is_root:
            args += ["-sS", "-sU"]
        run_nmap(args + [ip], f"checagens {ip}", progress)
        r2 = parse_host_scan(xml2, ip)
        if r2["ports"]:  # fase 2 incompleta: fica com o resultado da fase 1
            r2["os"] = r2["os"] or result["os"]
            result = r2
    if not result["os"] and result["host_info"].get("smb-os-discovery"):
        result["os"] = {"name": result["host_info"]["smb-os-discovery"], "accuracy": None}

    if ipv6_addrs and not STOPPING.is_set():
        check_ipv6_ports(result, ip, ipv6_addrs, outdir, ports, deep, timeout)
    for p in result["ports"]:
        p["exploits"] = find_exploits(p.get("product"), p.get("version"))
    return result


# scripts por serviço: (portas, trecho do nome do serviço, scripts)
SERVICE_SCRIPTS = [
    ({80, 443, 8000, 8008, 8080, 8443, 8888}, "http", ["http-title", "http-server-header", "http-methods"]),
    ({443, 8443, 993, 995, 465, 636, 3389}, "ssl", ["ssl-enum-ciphers", "ssl-cert"]),
    ({139, 445}, "microsoft-ds|netbios-ssn", ["smb-os-discovery", "smb-protocols", "smb-security-mode",
                                              "smb2-security-mode", "smb-enum-shares"]),
    ({22}, "ssh", ["ssh2-enum-algos", "ssh-auth-methods", "sshv1"]),
    ({21}, "ftp", ["ftp-anon", "ftp-syst"]),
    ({3389}, "ms-wbt-server|rdp", ["rdp-enum-encryption", "rdp-ntlm-info"]),
    ({161}, "snmp", ["snmp-info", "snmp-sysdescr"]),
    ({5900, 5901, 5902}, "vnc", ["vnc-info"]),
    ({6379}, "redis", ["redis-info"]),
    ({27017}, "mongodb", ["mongodb-info"]),
    ({11211}, "memcache", ["memcached-info"]),
    ({3306}, "mysql", ["mysql-info"]),
    ({1900}, "upnp", ["upnp-info"]),
    ({554}, "rtsp", ["rtsp-methods"]),
    ({123}, "ntp", ["ntp-info"]),
]
# testes de senha padrão/vazia: só com --default-creds (fazem tentativas de login)
CRED_SCRIPTS = [
    ({80, 443, 8000, 8080, 8443, 8888}, "http", ["http-default-accounts"]),
    ({3306}, "mysql", ["mysql-empty-password"]),
    ({1433}, "ms-sql", ["ms-sql-empty-password"]),
]


def select_scripts(ports, deep=False, default_creds=False):
    """Escolhe as checagens a partir dos serviços realmente abertos."""
    chosen = ["vuln", "vulners"]
    table = SERVICE_SCRIPTS + (CRED_SCRIPTS if default_creds else [])
    for p in ports:
        num = int(p["port"]) if str(p.get("port", "")).isdigit() else -1
        name = (p.get("service") or "").lower()
        if p.get("tunnel") == "ssl":
            name += " ssl"
        for nums, pat, scripts in table:
            if num in nums or (name and re.search(pat, name)):
                chosen += [x for x in scripts if x not in chosen]
    if deep:
        chosen.append("default")
    return chosen


def check_ipv6_ports(result, ip, ipv6_addrs, outdir, ports, deep, timeout):
    """Varre o IPv6 do aparelho: porta aberta só no IPv6 costuma escapar do firewall IPv4."""
    # endereço global primeiro (link-local exige %iface e nem sempre responde)
    addr = sorted(ipv6_addrs, key=lambda a: a.lower().startswith("fe80"))[0]
    xml_path = os.path.join(outdir, f"host_{_safe_name(addr)}.xml")
    args = ["-6", "-sV", "-T4", "--host-timeout", f"{timeout}s", "-oX", xml_path]
    if ports and "U:" not in ports:
        args += ["-p", ports]
    elif deep:
        args.append("-p-")
    run_nmap(args + [addr], f"scan IPv6 {addr}")
    v4 = {_port_key(p) for p in result["ports"]}
    for p in parse_host_scan(xml_path, addr)["ports"]:
        key = _port_key(p)
        if key in v4:
            continue
        p["ipv6"] = True
        result["ports"].append(p)
        result["vulns"].append({
            "port": p["port"], "id": "ipv6-only-port", "title": f"Porta {key} aberta só via IPv6",
            "output": f"{p.get('service') or '?'} responde em {addr}, mas não em {ip}.",
            "cves": [], "cvss": None, "severity": "medium",
            "fix": "Aplique no firewall IPv6 (ip6tables/nftables, roteador) as mesmas regras do IPv4, "
                   "ou desative o serviço/IPv6 se não for usado.",
        })
    _sort_and_count(result)


EXPLOIT_CACHE = {}


def exploit_query(product, version):
    """'OpenSSH', '7.4p1 Debian 10' -> 'OpenSSH 7.4' (searchsploit casa faixas de versão)."""
    if not product or not version:
        return None  # sem versão o resultado é ruído demais
    m = re.match(r"\d+(?:\.\d+)*", version.strip())
    if not m:
        return None
    return f"{product.strip()} {m.group(0)}"


def find_exploits(product, version):
    """Exploits públicos (Exploit-DB local via searchsploit) para o serviço; [] se indisponível."""
    q = exploit_query(product, version)
    if not q or not shutil.which("searchsploit") or STOPPING.is_set():
        return []
    if q in EXPLOIT_CACHE:
        return EXPLOIT_CACHE[q]
    try:
        out = subprocess.run(["searchsploit", "-j", "--exclude=/dos/", q],
                             capture_output=True, text=True, timeout=30).stdout
        rows = json.loads(out).get("RESULTS_EXPLOIT", [])
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        log(f"searchsploit falhou para '{q}': {e}", "~")
        rows = []
    found = [{"id": r.get("EDB-ID"), "title": r.get("Title"), "type": r.get("Type"),
              "cves": CVE_RE.findall(r.get("Codes") or "")} for r in rows[:15]]
    EXPLOIT_CACHE[q] = found
    return found


def extract_vuln_meta(output):
    """Extrai CVEs e a maior pontuação CVSS do texto de um script."""
    cves = []
    for c in CVE_RE.findall(output):
        cu = c.upper()
        if cu not in cves:
            cves.append(cu)
    scores = []
    for line in output.splitlines():
        low = line.lower()
        if "cve-" in low or "cvss" in low or "risk" in low:
            for m in re.findall(r"\b(\d{1,2}\.\d)\b", line):
                try:
                    v = float(m)
                    if 0 < v <= 10:
                        scores.append(v)
                except ValueError:
                    pass
    cvss = max(scores) if scores else None
    sev = classify_severity(cvss, output)
    return cves, cvss, sev


def classify_severity(cvss, output=""):
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        if cvss > 0:
            return "low"
    low = output.lower()
    if "risk factor: high" in low or "critical" in low:
        return "high"
    if "risk factor: medium" in low:
        return "medium"
    if "risk factor: low" in low:
        return "low"
    if "cve-" in low or "vulnerable" in low:
        return "medium"  # achado sem CVSS conhecido
    return "info"


def _severity_counts(vulns):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for v in vulns:
        counts[v.get("severity", "info")] = counts.get(v.get("severity", "info"), 0) + 1
    return counts


def parse_host_scan(xml_path, ip):
    result = {"ip": ip, "ports": [], "vulns": [], "os": None, "severity": {}, "host_info": {}}
    if not os.path.exists(xml_path):
        return result
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        log(f"XML do host {ip} ilegível (varredura incompleta).", "~")
        return result
    host = root.find("host")
    if host is None:
        return result

    # Sistema operacional
    osmatch = host.find("os/osmatch")
    if osmatch is not None:
        result["os"] = {"name": osmatch.get("name"), "accuracy": osmatch.get("accuracy")}

    def add_vuln(port, script):
        """Registra o achado; devolve False se o script for só informativo."""
        out = (script.get("output") or "").strip()
        sid = script.get("id")
        cfg = config_finding(sid, out)
        if cfg:
            sev, title = cfg
            result["vulns"].append({"port": port, "id": sid, "title": title, "output": out,
                                    "cves": [], "cvss": None, "severity": sev})
            return True
        if sid in INFO_SCRIPTS or not _looks_vulnerable(sid, out):
            return False
        cves, cvss, sev = extract_vuln_meta(out)
        result["vulns"].append({
            "port": port, "id": sid, "output": out,
            "cves": cves, "cvss": cvss, "severity": sev,
        })
        return True

    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        result["ports"].append({
            "port": port.get("portid"),
            "proto": port.get("protocol"),
            "service": svc.get("name") if svc is not None else None,
            "product": svc.get("product") if svc is not None else None,
            "version": svc.get("version") if svc is not None else None,
            "tunnel": svc.get("tunnel") if svc is not None else None,  # "ssl" = https
        })
        p = result["ports"][-1]
        bad = INSECURE_SERVICES.get(p["service"] or "")
        if bad and p["tunnel"] != "ssl":
            sev, title = bad
            result["vulns"].append({"port": p["port"], "id": "insecure-service", "title": title,
                                    "output": f"{p['service']} em {p['port']}/{p['proto']}",
                                    "cves": [], "cvss": None, "severity": sev})
        for script in port.findall("script"):
            if not add_vuln(port.get("portid"), script) and script.get("output"):
                p.setdefault("scripts", {})[script.get("id")] = _short(script.get("output"))

    for script in host.findall("hostscript/script"):
        out = script.get("output") or ""
        if add_vuln("host", script) or not out:
            continue
        os_line = re.search(r"OS: ([^\n]+)", out) if script.get("id") == "smb-os-discovery" else None
        result["host_info"][script.get("id")] = os_line.group(1).strip() if os_line else _short(out)

    # ordena por severidade (mais grave primeiro)
    products = {p["port"]: " ".join(filter(None, [p.get("product"), p.get("version")])) for p in result["ports"]}
    for v in result["vulns"]:
        v.setdefault("fix", remediation(v, products.get(v["port"])))
    _sort_and_count(result)
    return result


def _short(text, limit=160):
    """Saída de script informativo resumida a poucas linhas úteis."""
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
    return " · ".join(lines)[:limit]


def _sort_and_count(result):
    """Ordena por severidade (mais grave primeiro) e recalcula a contagem."""
    result["vulns"].sort(key=lambda v: (SEVERITY_ORDER.index(v.get("severity", "info")),
                                        -(v.get("cvss") or 0)))
    result["severity"] = _severity_counts(result["vulns"])


# scripts que só trazem informação: nunca viram achado por palavra-chave solta
INFO_SCRIPTS = {"http-title", "http-server-header", "smb-os-discovery", "ftp-syst", "ssh2-enum-algos",
                "ssh-auth-methods", "rdp-ntlm-info", "mysql-info", "rtsp-methods", "ntp-info",
                "ssl-enum-ciphers", "ssl-cert", "smb-security-mode", "smb2-security-mode", "smb-protocols",
                "smb-enum-shares", "sshv1", "vnc-info", "redis-info", "mongodb-info", "memcached-info",
                "rdp-enum-encryption", "http-methods", "upnp-info", "snmp-info", "snmp-sysdescr", "ftp-anon",
                "http-default-accounts", "mysql-empty-password", "ms-sql-empty-password"}

def config_finding(sid, output):
    """Traduz a saída das checagens de configuração em (severidade, título) ou None."""
    low = (output or "").lower()
    if sid == "ftp-anon" and "anonymous ftp login allowed" in low:
        return "medium", "FTP anônimo habilitado"
    if sid == "smb2-security-mode" and "not required" in low:
        return "medium", "Assinatura SMB não obrigatória (relay)"
    if sid == "smb-security-mode":
        if "account_used: guest" in low:
            return "medium", "SMB aceita acesso como convidado"
        if "message_signing: disabled" in low:
            return "medium", "Assinatura SMBv1 desabilitada (relay)"
    if sid == "ssl-enum-ciphers":
        m = re.search(r"least strength: ([a-f])", low)
        if m and m.group(1) in "cdef":
            return ("high" if m.group(1) == "f" else "medium"), f"TLS fraco (nota {m.group(1).upper()})"
    if sid == "ssl-cert":
        m = re.search(r"not valid after:\s*(\d{4}-\d{2}-\d{2})", low)
        if m:
            days = (datetime.strptime(m.group(1), "%Y-%m-%d") - datetime.now()).days
            if days < 0:
                return "low", f"Certificado TLS expirado em {m.group(1)}"
            if days < 30:
                return "low", f"Certificado TLS vence em {days + 1} dia(s) ({m.group(1)})"
    if sid in ("snmp-info", "snmp-sysdescr") and low:
        return "medium", "SNMP responde com a community padrão"
    if sid == "smb-protocols" and "smbv1" in low:
        return "high", "SMBv1 habilitado (alvo do WannaCry/EternalBlue)"
    if sid == "smb-enum-shares":
        if "anonymous access: read/write" in low:
            return "high", "Compartilhamento SMB com escrita sem senha"
        if "anonymous access: read" in low:
            return "medium", "Compartilhamento SMB legível sem senha"
    if sid == "sshv1" and "supports sshv1" in low:
        return "high", "Servidor aceita SSHv1 (quebrado)"
    if sid == "vnc-info" and re.search(r"security types:[^\n]*\n(?:\s+.*\n)*?\s+none \(1\)", low + "\n"):
        return "high", "VNC sem senha"
    if sid == "redis-info" and "version" in low and "auth" not in low:
        return "high", "Redis acessível sem autenticação"
    if sid == "mongodb-info" and "version" in low and not re.search(r"auth|unauthorized|requires", low):
        return "high", "MongoDB acessível sem autenticação"
    if sid == "memcached-info" and ("uptime" in low or "process id" in low):
        return "medium", "Memcached acessível sem autenticação"
    if sid == "rdp-enum-encryption" and "native rdp: success" in low:
        return "medium", "RDP aceita conexão sem NLA"
    if sid == "http-methods":
        m = re.search(r"potentially risky methods:([^\n]*)", low)
        if m and re.search(r"\b(put|delete)\b", m.group(1)):
            return "medium", "Métodos HTTP perigosos habilitados (PUT/DELETE)"
    if sid == "upnp-info" and low:
        return "low", "UPnP exposto (pode abrir portas no roteador sozinho)"
    if sid == "http-default-accounts" and re.search(r"\[[^\]]+\] at", low):
        return "critical", "Senha padrão de fábrica aceita"
    if sid in ("mysql-empty-password", "ms-sql-empty-password") and "empty password" in low and "has" in low:
        return "critical", "Banco de dados aceita senha vazia"
    return None


# serviços que trafegam credenciais em texto puro: (severidade, título)
INSECURE_SERVICES = {
    "telnet": ("medium", "Telnet: senhas trafegam em texto puro"),
    "login": ("medium", "rlogin: acesso remoto sem criptografia"),
    "shell": ("medium", "rsh: acesso remoto sem criptografia"),
    "exec": ("medium", "rexec: acesso remoto sem criptografia"),
    "ftp": ("low", "FTP sem criptografia"),
    "tftp": ("low", "TFTP sem autenticação"),
}

# dica de correção por script/achado (mais específico primeiro; prefixo terminado em "-")
FIXES = [
    ("insecure-service", "Desative o serviço ou troque por uma alternativa cifrada (SSH, SFTP/FTPS)."),
    ("ftp-anon", "Desative o login anônimo (vsftpd: anonymous_enable=NO)."),
    ("ftp-vsftpd-backdoor", "Servidor comprometido: reinstale o vsftpd de fonte oficial e investigue a máquina."),
    ("smb2-security-mode", "Exija assinatura SMB (GPO \"Digitally sign communications (always)\" / Samba: server signing = mandatory)."),
    ("smb-security-mode", "Desative acesso de convidado (Samba: map to guest = Never) e exija assinatura SMB."),
    ("smb-vuln-ms17-010", "Aplique o patch MS17-010 (EternalBlue) e desative o SMBv1."),
    ("smb-vuln-", "Aplique as atualizações de segurança do Windows/Samba e desative o SMBv1."),
    ("ssl-heartbleed", "Atualize o OpenSSL (>= 1.0.1g) e depois troque chaves e certificados."),
    ("ssl-poodle", "Desative o SSLv3."),
    ("sslv2-drown", "Desative o SSLv2 em todos os serviços que usam o mesmo certificado."),
    ("ssl-dh-params", "Use grupos Diffie-Hellman de 2048 bits ou mais, ou só ECDHE."),
    ("ssl-ccs-injection", "Atualize o OpenSSL."),
    ("ssl-enum-ciphers", "Desative TLS 1.0/1.1 e cifras fracas (RC4, 3DES, NULL, EXPORT); prefira TLS 1.2+ com AEAD."),
    ("ssl-cert", "Renove o certificado e automatize a renovação (ex.: certbot)."),
    ("smb-protocols", "Desative o SMBv1 (Windows: Set-SmbServerConfiguration -EnableSMB1Protocol $false; Samba: server min protocol = SMB2)."),
    ("smb-enum-shares", "Exija autenticação nos compartilhamentos e remova o acesso de convidado/anônimo."),
    ("sshv1", "Desative o protocolo 1 no sshd (Protocol 2) ou atualize o servidor SSH."),
    ("vnc-info", "Defina senha forte no VNC e restrinja o acesso (túnel SSH/VPN)."),
    ("redis-info", "Ative requirepass/ACL no Redis e escute só em 127.0.0.1 (bind)."),
    ("mongodb-info", "Ative authorization no MongoDB e escute só na rede interna (bindIp)."),
    ("memcached-info", "Escute só em 127.0.0.1 e desative UDP (-U 0)."),
    ("rdp-enum-encryption", "Exija NLA (Autenticação no Nível da Rede) nas configurações de Área de Trabalho Remota."),
    ("http-methods", "Desative PUT/DELETE no servidor web se não forem usados."),
    ("upnp-info", "Desative o UPnP no roteador se não precisar dele."),
    ("http-default-accounts", "Troque já a senha padrão de fábrica por uma senha forte e única."),
    ("mysql-empty-password", "Defina senha para todas as contas do banco e restrinja o acesso pela rede."),
    ("ms-sql-empty-password", "Defina senha para a conta 'sa' e restrinja o acesso pela rede."),
    ("snmp-sysdescr", "Troque a community padrão, use SNMPv3 ou restrinja o SNMP por ACL/firewall."),
    ("snmp-info", "Troque a community padrão, use SNMPv3 ou restrinja o SNMP por ACL/firewall."),
    ("http-slowloris", "Limite conexões e timeouts (Apache: mod_reqtimeout) ou coloque um proxy reverso na frente."),
    ("http-csrf", "Use tokens anti-CSRF e cookies SameSite."),
    ("http-stored-xss", "Escape a saída e valide a entrada; adicione Content-Security-Policy."),
    ("http-dombased-xss", "Evite inserir dados não confiáveis no DOM sem sanitizar; adicione Content-Security-Policy."),
    ("http-vuln-", "Atualize a aplicação/servidor web para a versão corrigida."),
    ("rdp-vuln-", "Aplique as atualizações do Windows e exija NLA no RDP."),
]


def remediation(v, product=None):
    """Dica curta de como corrigir o achado."""
    sid = v.get("id") or ""
    for key, fix in FIXES:
        if sid == key or (key.endswith("-") and sid.startswith(key)):
            return fix
    if v.get("cves"):
        what = product or "o serviço"
        return f"Atualize {what} para a versão corrigida do fornecedor; confira os CVEs listados."
    return "Confirme o achado manualmente e aplique a atualização ou configuração recomendada pelo fornecedor."


def _looks_vulnerable(sid, output):
    """Filtra ruído: só reporta scripts que indicam achado real."""
    if not output:
        return False
    low = output.lower()
    if CVE_RE.search(output):
        return True
    signals = ["vulnerable", "state: likely vulnerable", "exploit", "risk factor:"]
    negatives = ["not vulnerable", "couldn't", "no finding", "false"]
    if any(n in low for n in negatives) and "cve-" not in low:
        # permite se houver sinal forte além da negativa
        if not ("state: vulnerable" in low):
            return False
    return any(s in low for s in signals)


def _port_key(p):
    return f"{p.get('port')}/{p.get('proto')}"


def _vuln_key(v):
    return f"{v.get('port')}:{v.get('id')}"


def diff_reports(old_hosts, hosts):
    """Compara com uma varredura anterior: hosts/portas/vulns novos e sumidos."""
    old = {h["ip"]: h for h in old_hosts}
    new = {h["ip"]: h for h in hosts}
    changed = {}
    for ip, h in new.items():
        if ip not in old:
            continue
        o = old[ip]
        op = {_port_key(p) for p in o.get("ports", [])}
        np_ = {_port_key(p) for p in h.get("ports", [])}
        ov = {_vuln_key(v) for v in o.get("vulns", [])}
        nv = {_vuln_key(v) for v in h.get("vulns", [])}
        d = {"new_ports": sorted(np_ - op), "closed_ports": sorted(op - np_),
             "new_vulns": sorted(nv - ov), "fixed_vulns": sorted(ov - nv)}
        if any(d.values()):
            changed[ip] = d
    return {
        "new_hosts": sorted(set(new) - set(old)),
        "gone_hosts": sorted(set(old) - set(new)),
        "changed": changed,
    }


def load_previous(path):
    """Lê um relatorio.json anterior; devolve a lista de hosts ou None."""
    try:
        with open(path) as f:
            return json.load(f).get("hosts", [])
    except (OSError, ValueError, AttributeError) as e:
        log(f"Não consegui ler o relatório anterior ({path}): {e}", "~")
        return None


def write_html(report, path):
    """Relatório HTML autocontido (abre em qualquer navegador, sem dependências)."""
    e = lambda x: html.escape("" if x is None else str(x))
    colors = {"critical": "#ff4d6d", "high": "#ff8c42", "medium": "#f5c542",
              "low": "#4dabf7", "info": "#8a8f98"}
    t = report["totals"]
    parts = [
        "<!doctype html><html lang='pt-BR'><meta charset='utf-8'>",
        f"<title>netscan — {e(report['target'])}</title><style>",
        "body{font:14px system-ui,sans-serif;background:#0e0f12;color:#e6e7ea;max-width:1000px;margin:auto;padding:24px}",
        "h1{margin:0 0 4px}.dim{color:#8a8f98}.host{background:#16181d;padding:14px 18px;margin:12px 0;border-radius:6px}",
        "table{border-collapse:collapse;width:100%;margin:8px 0}td,th{text-align:left;padding:4px 8px;border-bottom:1px solid #262a33}",
        "pre{white-space:pre-wrap;font-size:12px;color:#b5b8bf;max-height:240px;overflow:auto}",
        "a{color:#46e39a}",
        ".tag{display:inline-block;padding:1px 6px;border-radius:3px;color:#000;font-weight:700;font-size:11px}",
        "</style>",
        f"<h1>netscan</h1><div class='dim'>Alvo {e(report['target'])} · {e(report['timestamp'])} · "
        f"{len(report['hosts'])} dispositivo(s)</div><p>",
    ]
    parts += [f"<span class='tag' style='background:{colors[s]}'>{t[s]} {s}</span> " for s in SEVERITY_ORDER]
    parts.append("</p>")
    if report.get("alerts"):
        parts.append("<div class='host'><h2>Alertas</h2><ul>")
        parts += [f"<li><span class='tag' style='background:{colors.get(a['level'], '#8a8f98')}'>{e(a['level'].upper())}</span> {e(a['text'])}</li>"
                  for a in report["alerts"]]
        parts.append("</ul></div>")
    an = report.get("analysis")
    if an:
        parts.append(f"<div class='host'><h2>Análise automática — risco {e(an['label'])} ({an['risk']}/100)</h2><ul>")
        parts += [f"<li>{e(s)}</li>" for s in an["summary"]]
        parts.append("</ul>")
        if an["top"]:
            parts.append("<h3>Corrija primeiro</h3><ol>")
            for t in an["top"]:
                parts.append(f"<li><b>{e(t['title'])}</b> — {e(t['ip'])} ({e(t['type'])}) porta {e(t['port'])} "
                             f"<span class='dim'>nota {t['score']} · {e('; '.join(t['reasons']))}</span>"
                             f"<br>{e(t.get('fix') or '')}</li>")
            parts.append("</ol>")
        parts.append("</div>")
    diff = report.get("diff")
    if diff:
        parts.append("<div class='host'><b>Mudanças desde a varredura anterior</b><ul>")
        parts += [f"<li>Novo dispositivo: {e(ip)}</li>" for ip in diff["new_hosts"]]
        parts += [f"<li>Sumiu: {e(ip)}</li>" for ip in diff["gone_hosts"]]
        for ip, d in diff["changed"].items():
            parts.append(f"<li>{e(ip)}: " + "; ".join(
                f"{k.replace('_', ' ')}: {e(', '.join(v))}" for k, v in d.items() if v) + "</li>")
        parts.append("</ul></div>")
    for h in report["hosts"]:
        ident = h.get("hostname") or h.get("vendor") or ""
        risk = f" · risco {h['risk']}/100" if "risk" in h else ""
        parts.append(f"<div class='host'><h2>{e(h['ip'])} <span class='dim'>{e(ident)} · {e(h.get('type_label', ''))}{risk}</span></h2>")
        meta = [x for x in [h.get("mac"), ", ".join(h.get("ipv6") or []), (h.get("os") or {}).get("name")] if x]
        if meta:
            parts.append(f"<div class='dim'>{e(' · '.join(meta))}</div>")
        if h.get("ports"):
            parts.append("<table><tr><th>Porta</th><th>Serviço</th><th>Versão</th></tr>")
            for p in h["ports"]:
                ver = " ".join(filter(None, [p.get("product"), p.get("version")]))
                parts.append(f"<tr><td>{e(_port_key(p))}</td><td>{e(p.get('service'))}</td><td>{e(ver)}</td></tr>")
                for x in p.get("exploits", []):
                    parts.append(f"<tr><td></td><td colspan='2' class='dim'>exploit "
                                 f"<a href='https://www.exploit-db.com/exploits/{e(x['id'])}'>EDB-{e(x['id'])}</a> "
                                 f"{e(x['title'])}</td></tr>")
            parts.append("</table>")
        for v in h.get("vulns", []):
            sev = v.get("severity", "info")
            cvss = f" CVSS {v['cvss']}" if v.get("cvss") else ""
            meta = " · ".join(filter(None, [f"nota {v['score']}" if "score" in v else "",
                                            f"confiança {v.get('confidence')}" if v.get("confidence") else "",
                                            "CISA KEV" if v.get("kev") else "",
                                            f"EPSS {round(v['epss'] * 100)}%" if v.get("epss") else ""]))
            parts.append(f"<p><span class='tag' style='background:{colors[sev]}'>{e(sev.upper())}{cvss}</span> "
                         f"<span class='dim'>{e(meta)}</span> "
                         f"porta {e(v['port'])} · {e(v['id'])} {e(v.get('title'))} <span class='dim'>{e(', '.join(v.get('cves', [])[:10]))}</span></p>"
                         + (f"<p><b>Correção:</b> {e(v['fix'])}</p>" if v.get("fix") else "")
                         + f"<pre>{e(v['output'])}</pre>")
        parts.append("</div>")
    with open(path, "w") as f:
        f.write("".join(parts))


def write_csv(hosts, path):
    """Uma linha por porta e uma por achado (planilha/ticket)."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "hostname", "mac", "fabricante", "dispositivo", "risco_host", "tipo", "porta",
                    "servico", "versao", "severidade", "achado", "cvss", "cves", "exploits", "correcao",
                    "nota", "confianca", "kev", "epss"])
        for h in hosts:
            base = [h["ip"], h.get("hostname") or "", h.get("mac") or "", h.get("vendor") or "",
                    h.get("type_label") or "", h.get("risk", "")]
            for p in h.get("ports", []):
                ver = " ".join(filter(None, [p.get("product"), p.get("version")]))
                w.writerow(base + ["porta", _port_key(p), p.get("service") or "", ver, "", "", "", "",
                                   " ".join(f"EDB-{x['id']}" for x in p.get("exploits", []))])
            for v in h.get("vulns", []):
                w.writerow(base + ["achado", v["port"], "", "", v.get("severity"),
                                   v.get("title") or v["id"], v.get("cvss") or "",
                                   " ".join(v.get("cves", [])), "", v.get("fix") or "",
                                   v.get("score", ""), v.get("confidence") or "", " ".join(v.get("kev") or []),
                                   v.get("epss") if v.get("epss") is not None else ""])


def write_report(target, hosts, outdir, diff=None, analysis_=None, alerts=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    totals = {s: 0 for s in SEVERITY_ORDER}
    for h in hosts:
        for v in h.get("vulns", []):
            totals[v.get("severity", "info")] += 1
    total_vulns = sum(totals.values())

    report = {"target": target, "timestamp": ts, "totals": totals, "hosts": hosts}
    if diff is not None:
        report["diff"] = diff
    if analysis_ is not None:
        report["analysis"] = analysis_
    if alerts is not None:
        report["alerts"] = alerts
    json_path = os.path.join(outdir, "relatorio.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    html_path = os.path.join(outdir, "relatorio.html")
    write_html(report, html_path)
    write_csv(hosts, os.path.join(outdir, "relatorio.csv"))

    txt_path = os.path.join(outdir, "relatorio.txt")
    lines = [
        "=" * 72,
        f"RELATÓRIO DE VARREDURA — {ts}",
        f"Alvo: {target}",
        f"Dispositivos ativos: {len(hosts)}",
        f"Vulnerabilidades: {total_vulns}  "
        f"(críticas {totals['critical']}, altas {totals['high']}, "
        f"médias {totals['medium']}, baixas {totals['low']}, info {totals['info']})",
        "=" * 72,
        "",
    ]
    if alerts:
        lines.append("ALERTAS")
        lines += [f"  [{a['level'].upper()}] {a['text']}" for a in alerts]
        lines.append("")
    if analysis_:
        lines.append("ANÁLISE AUTOMÁTICA")
        lines += [f"  {s}" for s in analysis_["summary"]]
        if analysis_["top"]:
            lines.append("")
            lines.append("CORRIJA PRIMEIRO")
            for i, t in enumerate(analysis_["top"], 1):
                lines.append(f"  {i}. [{t['score']}] {t['ip']} ({t['type']}) porta {t['port']} — {t['title']}")
                if t["reasons"]:
                    lines.append(f"     Por quê: {'; '.join(t['reasons'])}")
                if t.get("fix"):
                    lines.append(f"     Como: {t['fix']}")
        lines.append("")
    if diff:
        lines.append("MUDANÇAS DESDE A VARREDURA ANTERIOR")
        lines += [f"  + novo dispositivo: {ip}" for ip in diff["new_hosts"]]
        lines += [f"  - sumiu: {ip}" for ip in diff["gone_hosts"]]
        for ip, d in diff["changed"].items():
            for k, v in d.items():
                if v:
                    lines.append(f"  ~ {ip} {k.replace('_', ' ')}: {', '.join(v)}")
        lines.append("")
    for h in hosts:
        ident = h.get("hostname") or h.get("vendor") or "desconhecido"
        risk = f"  · risco {h['risk']}/100 ({h.get('risk_label')})" if "risk" in h else ""
        lines.append(f"[{h['ip']}] {ident} — {h.get('type_label', '?')}{risk}")
        if h.get("mac"):
            lines.append(f"    MAC: {h['mac']}  Fabricante: {h.get('vendor') or '?'}")
        if h.get("ipv6"):
            lines.append(f"    IPv6: {', '.join(h['ipv6'])}")
        if h.get("os") and h["os"].get("name"):
            lines.append(f"    SO (estimado): {h['os']['name']} ({h['os'].get('accuracy')}%)")
        ports = h.get("ports", [])
        if ports:
            lines.append("    Portas abertas:")
            for p in ports:
                svc = p.get("service") or "?"
                prod = " ".join(filter(None, [p.get("product"), p.get("version")]))
                lines.append(f"      {p['port']}/{p['proto']}  {svc}  {prod}".rstrip())
                for x in p.get("exploits", []):
                    lines.append(f"          exploit EDB-{x['id']}: {x['title']}")
        vulns = h.get("vulns", [])
        if vulns:
            lines.append(f"    *** {len(vulns)} ACHADO(S) DE VULNERABILIDADE ***")
            for v in vulns:
                tag = v.get("severity", "info").upper()
                score = f" CVSS {v['cvss']}" if v.get("cvss") else ""
                cves = (" " + ", ".join(v["cves"][:6])) if v.get("cves") else ""
                title = f" — {v['title']}" if v.get("title") else ""
                lines.append(f"      [{tag}{score}] porta {v['port']} · {v['id']}{title}{cves}")
                extra = [f"nota {v['score']}"] if "score" in v else []
                if v.get("confidence"):
                    extra.append(f"confiança {v['confidence']}")
                if v.get("kev"):
                    extra.append("CISA KEV: " + ", ".join(v["kev"]))
                if v.get("epss"):
                    extra.append(f"EPSS {round(v['epss'] * 100)}%")
                if extra:
                    lines.append(f"          ({' · '.join(extra)})")
                for n in v.get("notes", []):
                    lines.append(f"          Atenção: {n}")
                if v.get("fix"):
                    lines.append(f"          Correção: {v['fix']}")
                for ol in v["output"].splitlines():
                    if ol.strip():
                        lines.append(f"          {ol.strip()}")
        else:
            lines.append("    Nenhuma vulnerabilidade sinalizada pelos scripts.")
        lines.append("")
    lines.append("=" * 72)
    lines.append(f"TOTAL: {len(hosts)} dispositivo(s), {total_vulns} achado(s).")
    lines.append("=" * 72)
    content = "\n".join(lines)
    with open(txt_path, "w") as f:
        f.write(content + "\n")
    if not JSON_STREAM:
        print("\n" + content)
    log(f"Relatório salvo em: {txt_path}", "+")
    log(f"JSON salvo em:      {json_path}", "+")
    log(f"HTML salvo em:      {html_path}", "+")
    return totals


def service_scan_args(args):
    """Opções de varredura repassadas ao serviço do systemd."""
    out = []
    for flag, val in (("-t", args.target), ("-p", args.ports), ("-x", args.exclude)):
        if val:
            out += [flag, val]
    for flag, on in (("--fast", args.fast), ("--deep", args.deep), ("--udp", args.udp), ("--ipv6", args.ipv6),
                     ("--no-ping", args.no_ping), ("--default-creds", args.default_creds), ("--offline", args.offline)):
        if on:
            out.append(flag)
    out += ["-w", str(args.workers), "--host-timeout", str(args.host_timeout)]
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Varredura de rede: descoberta de dispositivos + checagem de vulnerabilidades (nmap).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use SOMENTE em redes próprias ou com autorização explícita.",
    )
    parser.add_argument("-t", "--target", help="Alvo(s) (CIDR, IP, range ou hostname; vários separados por vírgula/espaço). Padrão: todas as sub-redes locais.")
    parser.add_argument("-o", "--outdir", default=None, help="Diretório de saída (padrão: ./resultados_AAAA-MM-DD_HHMMSS).")
    parser.add_argument("--fast", action="store_true", help="Só descoberta + serviços, sem scripts de vulnerabilidade.")
    parser.add_argument("--deep", action="store_true", help="Varredura profunda: todas as portas (-p-) e scripts extras.")
    parser.add_argument("-p", "--ports", help="Portas a varrer (sintaxe do nmap: 22,80,443 ou 1-1024 ou T:80,U:53).")
    parser.add_argument("-x", "--exclude", help="Alvos a excluir da varredura (IPs/CIDRs separados por vírgula).")
    parser.add_argument("--udp", action="store_true", help="Inclui portas UDP comuns (requer root).")
    parser.add_argument("--no-ping", action="store_true", help="Não testa se o host está ativo (-Pn): útil quando ICMP/ARP é bloqueado.")
    parser.add_argument("-w", "--workers", type=int, default=1, help="Hosts analisados em paralelo (1-16, padrão 1).")
    parser.add_argument("--host-timeout", type=int, default=1200, help="Tempo máximo por host, em segundos (padrão 1200).")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Também descobre vizinhos IPv6 (multicast) e procura portas abertas só via IPv6.")
    parser.add_argument("--default-creds", action="store_true", help="Testa senhas padrão de fábrica/vazias (faz tentativas de login; desligado por padrão).")
    parser.add_argument("--offline", action="store_true", help="Não baixa CISA KEV/EPSS (usa só o cache local).")
    parser.add_argument("--compare", help="relatorio.json de uma varredura anterior (ou 'latest' para a mais recente) para mostrar o que mudou.")
    parser.add_argument("--notify", action="store_true", help="Envia os alertas (webhook/Telegram/desktop, configurados por variáveis de ambiente).")
    parser.add_argument("--keep", type=int, default=0, help="Mantém só as N varreduras mais recentes na pasta atual (0 = todas).")
    parser.add_argument("--install-service", action="store_true", help="Instala o monitoramento periódico no systemd (root) com as opções de varredura dadas.")
    parser.add_argument("--uninstall-service", action="store_true", help="Remove o monitoramento periódico do systemd (root).")
    parser.add_argument("--every", type=int, default=60, help="Intervalo do serviço em minutos (padrão 60).")
    parser.add_argument("--json-stream", action="store_true", help="Emite eventos JSON (um por linha) no stdout, para a interface.")
    args = parser.parse_args()

    global JSON_STREAM
    JSON_STREAM = args.json_stream

    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGINT, _terminate)

    check_prereqs()

    def fatal(msg, code=2):
        log(msg, "!")
        emit("fatal", error=msg)
        sys.exit(code)

    if args.ports and not PORTS_RE.match(args.ports):
        fatal("Portas inválidas. Ex.: 22,80,443 ou 1-1024 ou T:80,U:53.")
    if args.exclude and not validate_target(args.exclude):
        fatal("Lista de exclusão inválida.")
    if not 1 <= args.workers <= 16:
        fatal("--workers deve estar entre 1 e 16.")
    if not 30 <= args.host_timeout <= 86400:
        fatal("--host-timeout deve estar entre 30 e 86400 segundos.")

    if args.install_service or args.uninstall_service:
        if args.target and not validate_target(args.target):
            fatal("Alvo inválido.")
        try:
            if args.uninstall_service:
                automation.uninstall_service(log)
                emit("service", ok=True, action="uninstall")
            else:
                automation.install_service(os.path.abspath(__file__), args.every, service_scan_args(args), log)
                emit("service", ok=True, action="install", every=args.every)
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            fatal(f"Falha ao configurar o serviço: {e}", 1)
        return

    is_root = (os.geteuid() == 0)
    if not is_root:
        log("Sem root: ARP scan, detecção de SO e alguns scripts têm cobertura menor.", "~")
        if args.udp:
            log("--udp exige root; ignorando UDP.", "~")

    compare = automation.latest_report() if args.compare == "latest" else args.compare
    if args.compare == "latest" and not compare:
        log("Nenhuma varredura anterior para comparar (primeira execução).", "~")
    previous = load_previous(compare) if compare else None

    target = args.target
    if target:
        target = validate_target(target)
        if not target:
            fatal("Alvo inválido. Use IP, CIDR (192.168.0.0/24), range ou hostname.")
    else:
        subs = detect_local_subnets()
        if not subs:
            fatal("Não foi possível detectar a sub-rede local. Informe um alvo com -t.", 1)
        target = " ".join(subs)
        log(f"Sub-rede(s) local(is) detectada(s): {target}")

    outdir = args.outdir or os.path.join(
        os.getcwd(), f"resultados_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}"
    )
    try:
        os.makedirs(outdir, exist_ok=True)
    except OSError as e:
        fatal(f"Falha ao criar diretório de saída: {e}", 1)
    log(f"Resultados em: {outdir}")
    emit("start", target=target, outdir=outdir, fast=args.fast, deep=args.deep, root=is_root,
         workers=args.workers, udp=args.udp and is_root)

    gateway = detect_gateway()
    intel = analysis.Intel(offline=args.offline, log=log)

    emit("phase", phase="discovery")
    # vizinhos IPv6 por multicast só fazem sentido na rede local (sem alvo explícito)
    hosts = discover_hosts(target, outdir, exclude=args.exclude, no_ping=args.no_ping,
                           ipv6=args.ipv6 and not args.target)
    if args.no_ping and len(hosts) > 1024:
        fatal(f"--no-ping com {len(hosts)} endereços é grande demais; restrinja o alvo (máx. 1024).")
    if not hosts:
        log("Nenhum dispositivo ativo encontrado.", "!")
    else:
        log(f"{len(hosts)} dispositivo(s) encontrado(s): " + ", ".join(h["ip"] for h in hosts), "+")
    emit("discovery", hosts=hosts)

    if hosts:
        emit("phase", phase="scan")
        total = len(hosts)
        done = 0

        def work(i, h):
            log(f"[{i}/{total}] Analisando {h['ip']} ...")
            emit("host_start", index=i, total=total, ip=h["ip"])
            scan = scan_host(h["ip"], outdir, fast=args.fast, deep=args.deep, is_root=is_root,
                             ports=args.ports, udp=args.udp, no_ping=args.no_ping,
                             timeout=args.host_timeout,
                             ipv6_addrs=h.get("ipv6") if args.ipv6 else None,
                             default_creds=args.default_creds)
            for k in ("ports", "vulns", "os", "severity", "host_info"):
                h[k] = scan[k]
            try:
                analysis.analyze_host(h, intel, gateway)
            except Exception as e:  # análise nunca derruba a varredura
                log(f"Falha na análise de {h['ip']}: {e}", "~")
            return h

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(work, i, h) for i, h in enumerate(hosts, 1)]
            for fut in as_completed(futures):
                done += 1
                try:
                    h = fut.result()
                except Exception as e:  # um host com falha não derruba a varredura
                    log(f"Falha ao analisar um host: {e}", "!")
                    continue
                emit("host_done", index=done, total=total, host=h)
        # no -Pn, IPs sem nenhuma porta aberta provavelmente nem existem
        if args.no_ping:
            hosts = [h for h in hosts if h.get("ports")]

    diff = diff_reports(previous, hosts) if previous is not None else None
    if diff:
        log(f"Comparação: {len(diff['new_hosts'])} novo(s), {len(diff['gone_hosts'])} sumido(s), "
            f"{len(diff['changed'])} alterado(s).", "+")
    for h in hosts:
        if "risk" not in h:  # host que falhou ou não foi analisado
            analysis.analyze_host(h, None, gateway)
    an = analysis.analyze_network(hosts, diff)
    for s in an["summary"]:
        log(s, "+")
    try:
        new_keys, baseline = automation.update_inventory(hosts)
    except OSError as e:
        log(f"Não consegui atualizar o inventário: {e}", "~")
        new_keys, baseline = [], True
    if baseline and hosts:
        log("Inventário criado: os próximos dispositivos novos vão gerar alerta.", "+")
    alerts = automation.build_alerts(hosts, diff, new_keys, baseline)
    for a in alerts:
        log(f"ALERTA [{a['level']}] {a['text']}", "!")
    if args.notify and alerts:
        sent = automation.notify(alerts, f"risco {an['label']} ({an['risk']}/100), {len(alerts)} alerta(s)", log)
        log(f"Alertas enviados por: {', '.join(sent) or 'nenhum canal configurado'}.", "+")
    totals = write_report(target, hosts, outdir, diff, an, alerts)
    if args.keep:
        removed = automation.prune_results(".", args.keep)
        if removed:
            log(f"{removed} varredura(s) antiga(s) removida(s) (--keep {args.keep}).")
    emit("done", outdir=outdir, hosts=hosts, totals=totals, diff=diff, analysis=an, alerts=alerts)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _terminate(signal.SIGINT, None)
