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
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime


JSON_STREAM = False
CURRENT_PROC = None  # processo nmap em execução (para encerramento limpo)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TARGET_RE = re.compile(r"^[A-Za-z0-9.\-/,: ]+$")  # IP, CIDR, range, hostname


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
        print(json.dumps({"event": event, **data}, ensure_ascii=False), flush=True)


def _terminate(signum, frame):
    """Encerra o nmap filho antes de sair (robustez ao parar a varredura)."""
    global CURRENT_PROC
    if CURRENT_PROC and CURRENT_PROC.poll() is None:
        try:
            CURRENT_PROC.terminate()
            CURRENT_PROC.wait(timeout=5)
        except Exception:
            try:
                CURRENT_PROC.kill()
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


def run_nmap(args, label):
    """Roda o nmap, rastreando o processo para encerramento limpo.
    Retorna True se o nmap terminou com código 0. Mesmo em falha parcial,
    o XML gerado ainda é lido pelo chamador."""
    global CURRENT_PROC
    log(f"Executando: nmap {' '.join(args)}", "~")
    stdout = subprocess.DEVNULL if JSON_STREAM else None
    stderr = subprocess.DEVNULL if JSON_STREAM else None
    try:
        CURRENT_PROC = subprocess.Popen(["nmap"] + args, stdout=stdout, stderr=stderr)
    except FileNotFoundError:
        log("nmap não encontrado durante a execução.", "!")
        return False
    except Exception as e:
        log(f"Falha ao iniciar nmap ({label}): {e}", "!")
        return False
    try:
        rc = CURRENT_PROC.wait()
    except KeyboardInterrupt:
        _terminate(signal.SIGINT, None)
    finally:
        CURRENT_PROC = None
    if rc != 0:
        log(f"nmap retornou código {rc} ({label}) — usando resultado parcial se houver.", "~")
    return rc == 0


def discover_hosts(target, outdir):
    """Ping/ARP scan para descobrir hosts ativos."""
    log(f"Descobrindo dispositivos em {target} ...")
    xml_path = os.path.join(outdir, "discovery.xml")
    run_nmap(["-sn", "-PR", "-oX", xml_path, target], "descoberta")
    if not os.path.exists(xml_path):
        return []
    hosts = []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        log(f"Erro ao ler XML de descoberta: {e}", "!")
        return []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = mac = vendor = name = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        hn = host.find("hostnames/hostname")
        if hn is not None:
            name = hn.get("name")
        if ip:
            hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": name})
    return hosts


def scan_host(ip, outdir, fast=False, deep=False, is_root=False):
    """Detecta serviços, SO e (se não fast) vulnerabilidades."""
    safe = ip.replace(".", "_").replace(":", "_")
    xml_path = os.path.join(outdir, f"host_{safe}.xml")
    args = ["-sV", "-T4", "--host-timeout", "1200s", "-oX", xml_path]
    if is_root:
        args.append("-O")  # detecção de SO exige root
    if deep:
        args.append("-p-")  # todas as 65535 portas
    if not fast:
        scripts = "vuln,vulners"
        if deep:
            scripts += ",default,http-enum,http-headers,ssl-enum-ciphers,ssh2-enum-algos"
        args += ["--script", scripts, "--script-args", "mincvss=0.0"]
    args.append(ip)
    run_nmap(args, f"scan {ip}")
    return parse_host_scan(xml_path, ip)


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
    result = {"ip": ip, "ports": [], "vulns": [], "os": None, "severity": {}}
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
        out = (script.get("output") or "").strip()
        sid = script.get("id")
        if not _looks_vulnerable(sid, out):
            return
        cves, cvss, sev = extract_vuln_meta(out)
        result["vulns"].append({
            "port": port, "id": sid, "output": out,
            "cves": cves, "cvss": cvss, "severity": sev,
        })

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
        })
        for script in port.findall("script"):
            add_vuln(port.get("portid"), script)

    for script in host.findall("hostscript/script"):
        add_vuln("host", script)

    # ordena por severidade (mais grave primeiro)
    result["vulns"].sort(key=lambda v: (SEVERITY_ORDER.index(v.get("severity", "info")),
                                        -(v.get("cvss") or 0)))
    result["severity"] = _severity_counts(result["vulns"])
    return result


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


def write_report(target, hosts, outdir):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    totals = {s: 0 for s in SEVERITY_ORDER}
    for h in hosts:
        for v in h.get("vulns", []):
            totals[v.get("severity", "info")] += 1
    total_vulns = sum(totals.values())

    report = {"target": target, "timestamp": ts, "totals": totals, "hosts": hosts}
    json_path = os.path.join(outdir, "relatorio.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

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
    for h in hosts:
        ident = h.get("hostname") or h.get("vendor") or "desconhecido"
        lines.append(f"[{h['ip']}] {ident}")
        if h.get("mac"):
            lines.append(f"    MAC: {h['mac']}  Fabricante: {h.get('vendor') or '?'}")
        if h.get("os") and h["os"].get("name"):
            lines.append(f"    SO (estimado): {h['os']['name']} ({h['os'].get('accuracy')}%)")
        ports = h.get("ports", [])
        if ports:
            lines.append("    Portas abertas:")
            for p in ports:
                svc = p.get("service") or "?"
                prod = " ".join(filter(None, [p.get("product"), p.get("version")]))
                lines.append(f"      {p['port']}/{p['proto']}  {svc}  {prod}".rstrip())
        vulns = h.get("vulns", [])
        if vulns:
            lines.append(f"    *** {len(vulns)} ACHADO(S) DE VULNERABILIDADE ***")
            for v in vulns:
                tag = v.get("severity", "info").upper()
                score = f" CVSS {v['cvss']}" if v.get("cvss") else ""
                cves = (" " + ", ".join(v["cves"][:6])) if v.get("cves") else ""
                lines.append(f"      [{tag}{score}] porta {v['port']} · {v['id']}{cves}")
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


def main():
    parser = argparse.ArgumentParser(
        description="Varredura de rede: descoberta de dispositivos + checagem de vulnerabilidades (nmap).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use SOMENTE em redes próprias ou com autorização explícita.",
    )
    parser.add_argument("-t", "--target", help="Alvo (CIDR, IP, range ou hostname). Padrão: auto-detecta a sub-rede local.")
    parser.add_argument("-o", "--outdir", default=None, help="Diretório de saída (padrão: ./resultados_AAAA-MM-DD_HHMMSS).")
    parser.add_argument("--fast", action="store_true", help="Só descoberta + serviços, sem scripts de vulnerabilidade.")
    parser.add_argument("--deep", action="store_true", help="Varredura profunda: todas as portas (-p-) e scripts extras.")
    parser.add_argument("--json-stream", action="store_true", help="Emite eventos JSON (um por linha) no stdout, para a interface.")
    args = parser.parse_args()

    global JSON_STREAM
    JSON_STREAM = args.json_stream

    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGINT, _terminate)

    check_prereqs()

    is_root = (os.geteuid() == 0)
    if not is_root:
        log("Sem root: ARP scan, detecção de SO e alguns scripts têm cobertura menor.", "~")

    target = args.target
    if target:
        target = validate_target(target)
        if not target:
            log("Alvo inválido. Use IP, CIDR (192.168.0.0/24), range ou hostname.", "!")
            emit("fatal", error="Alvo inválido.")
            sys.exit(2)
    else:
        subs = detect_local_subnets()
        if not subs:
            log("Não detectei sub-rede local. Informe com -t.", "!")
            emit("fatal", error="Não foi possível detectar a sub-rede local. Informe um alvo.")
            sys.exit(1)
        target = subs[0]
        log(f"Sub-rede local detectada: {target}" + (f" (outras: {', '.join(subs[1:])})" if len(subs) > 1 else ""))

    outdir = args.outdir or os.path.join(
        os.getcwd(), f"resultados_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}"
    )
    try:
        os.makedirs(outdir, exist_ok=True)
    except OSError as e:
        log(f"Não consegui criar o diretório de saída: {e}", "!")
        emit("fatal", error=f"Falha ao criar diretório de saída: {e}")
        sys.exit(1)
    log(f"Resultados em: {outdir}")
    emit("start", target=target, outdir=outdir, fast=args.fast, deep=args.deep, root=is_root)

    emit("phase", phase="discovery")
    hosts = discover_hosts(target, outdir)
    if not hosts:
        log("Nenhum dispositivo ativo encontrado.", "!")
        emit("discovery", hosts=[])
        write_report(target, [], outdir)
        emit("done", outdir=outdir, hosts=[], totals={s: 0 for s in SEVERITY_ORDER})
        return
    log(f"{len(hosts)} dispositivo(s) encontrado(s): " + ", ".join(h["ip"] for h in hosts), "+")
    emit("discovery", hosts=hosts)

    emit("phase", phase="scan")
    for i, h in enumerate(hosts, 1):
        log(f"[{i}/{len(hosts)}] Analisando {h['ip']} ...")
        emit("host_start", index=i, total=len(hosts), ip=h["ip"])
        scan = scan_host(h["ip"], outdir, fast=args.fast, deep=args.deep, is_root=is_root)
        h["ports"] = scan["ports"]
        h["vulns"] = scan["vulns"]
        h["os"] = scan["os"]
        h["severity"] = scan["severity"]
        emit("host_done", index=i, total=len(hosts), host=h)

    write_report(target, hosts, outdir)
    totals = {s: 0 for s in SEVERITY_ORDER}
    for h in hosts:
        for v in h.get("vulns", []):
            totals[v.get("severity", "info")] += 1
    emit("done", outdir=outdir, hosts=hosts, totals=totals)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _terminate(signal.SIGINT, None)
