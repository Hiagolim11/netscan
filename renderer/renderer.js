'use strict';

const $ = (id) => document.getElementById(id);

const els = {
  target: $('target'), sudo: $('sudo'), modeHint: $('modeHint'),
  prefsBtn: $('prefsBtn'), prefsOverlay: $('prefsOverlay'), prefsClose: $('prefsClose'), logoutBtn: $('logoutBtn'),
  webhook: $('webhook'), tgToken: $('tgToken'), tgTokenHint: $('tgTokenHint'), tgChat: $('tgChat'), minLevel: $('minLevel'),
  desktopNotify: $('desktopNotify'), testNotify: $('testNotify'), testResult: $('testResult'),
  schedEvery: $('schedEvery'), schedStatus: $('schedStatus'), downloadCsv: $('downloadCsv'),
  ports: $('ports'), exclude: $('exclude'), workers: $('workers'),
  udp: $('udp'), noPing: $('noPing'), ipv6: $('ipv6'), defaultCreds: $('defaultCreds'), compare: $('compare'),
  toolbar: $('toolbar'), filter: $('filter'), onlyVuln: $('onlyVuln'), expandAll: $('expandAll'),
  openHtml: $('openHtml'), exportPdf: $('exportPdf'), progress: $('progress'), progressFill: $('progressFill'),
  analysis: $('analysis'), anRisk: $('anRisk'), anLevel: $('anLevel'), anSummary: $('anSummary'),
  anTop: $('anTop'), anTopWrap: $('anTopWrap'), anAlerts: $('anAlerts'),
  svcStatus: $('svcStatus'), svcEvery: $('svcEvery'), svcInstall: $('svcInstall'), svcRemove: $('svcRemove'),
  noMatch: $('noMatch'), emptyBig: $('emptyBig'), emptySub: $('emptySub'), clearLog: $('clearLog'), repeat: $('repeat'), history: $('history'),
  start: $('startBtn'), stop: $('stopBtn'),
  log: $('log'),
  statHosts: $('statHosts'), statPorts: $('statPorts'), statVulns: $('statVulns'), sevBreak: $('sevBreak'),
  empty: $('empty'), devices: $('devices'),
  barTarget: $('barTarget'), barPhase: $('barPhase'),
  report: $('reportBar'), reportText: $('reportText'), openReport: $('openReport'),
  // modal
  pwOverlay: $('pwOverlay'), pwForm: $('pwForm'), pwInput: $('pwInput'),
  pwError: $('pwError'), pwCancel: $('pwCancel'),
};

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'críticas', high: 'altas', medium: 'médias', low: 'baixas', info: 'info' };

let state = { hosts: new Map(), outdir: null, running: false, pendingOpts: null, monitorTimer: null, monitorOff: false };

// apelidos/notas por dispositivo (MAC, ou IP se não houver MAC), só nesta máquina
function loadAliases() { try { return JSON.parse(localStorage.getItem('netscan.aliases')) || {}; } catch (_) { return {}; } }
const aliases = loadAliases();
function aliasKey(h) { return h.mac || h.ip; }
function saveAlias(h, text) {
  const k = aliasKey(h);
  if (text) aliases[k] = text; else delete aliases[k];
  try { localStorage.setItem('netscan.aliases', JSON.stringify(aliases)); } catch (_) {}
}

const modeInputs = () => [...document.querySelectorAll('input[name="mode"]')];
function currentMode() { return (modeInputs().find((i) => i.checked) || {}).value || 'normal'; }

function currentOpts() {
  const mode = currentMode();
  return {
    target: els.target.value.trim() || null,
    fast: mode === 'fast',
    deep: mode === 'deep',
    useSudo: els.sudo.checked,
    ports: els.ports.value.trim() || null,
    exclude: els.exclude.value.trim() || null,
    workers: els.workers.value,
    udp: els.udp.checked,
    noPing: els.noPing.checked,
    ipv6: els.ipv6.checked,
    defaultCreds: els.defaultCreds.checked,
    compare: els.compare.value,
    repeat: Math.max(0, parseInt(els.repeat.value, 10) || 0),
  };
}

function setRunning(on) {
  state.running = on;
  for (const el of [els.start]) el.disabled = on;
  els.stop.disabled = !on;
  for (const el of [els.target, ...modeInputs(), els.sudo, els.ports, els.exclude,
    els.workers, els.udp, els.noPing, els.ipv6, els.defaultCreds, els.compare, els.repeat]) el.disabled = on;
  if (state.monitorTimer) els.stop.disabled = false; // permite parar o monitoramento na espera
  if (!on) {
    setProgress('off');
    if (!state.hosts.size) { // cancelado/erro antes de achar algo: volta ao estado inicial
      els.emptyBig.textContent = 'A rede ainda não foi varrida.';
      els.emptySub.textContent = 'Inicie uma varredura e os dispositivos aparecem aqui, um a um, conforme são encontrados.';
    }
  }
  document.querySelectorAll('.act-rescan').forEach((b) => { b.disabled = on; });
}

function logLine(text, cls) {
  const span = document.createElement('span');
  span.className = 'ln' + (cls ? ' ' + cls : '');
  span.textContent = text;
  els.log.appendChild(span);
  els.log.scrollTop = els.log.scrollHeight;
}

function recount() {
  let ports = 0;
  const totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const h of state.hosts.values()) {
    ports += (h.ports || []).length;
    for (const v of (h.vulns || [])) totals[v.severity || 'info']++;
  }
  const vulns = SEV.reduce((a, s) => a + totals[s], 0);
  els.statHosts.textContent = state.hosts.size;
  els.statPorts.textContent = ports;
  els.statVulns.textContent = vulns;
  els.statVulns.parentElement.classList.toggle('zero', !vulns);
  els.sevBreak.innerHTML = SEV
    .filter((s) => totals[s] > 0)
    .map((s) => `<span class="sev-chip c-${s}"><b>${totals[s]}</b>${SEV_LABEL[s]}</span>`)
    .join('');
}

function cssId(ip) { return ip.replace(/[^a-z0-9]/gi, '_'); }
function esc(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }

function deviceNode(ip) {
  let node = document.getElementById('dev-' + cssId(ip));
  if (node) return node;
  node = document.createElement('li');
  node.className = 'device';
  node.id = 'dev-' + cssId(ip);
  node.innerHTML = `
    <div class="device-head">
      <span class="device-ip"></span>
      <span class="device-name"></span>
      <span class="device-type" hidden></span>
      <span class="device-prog"></span>
      <span class="device-badges">
        <span class="device-sevdots"></span>
        <span class="badge-ports"><span class="badge-num">0</span><span class="badge-lbl">portas</span></span>
        <span class="badge-vuln"><span class="badge-num">0</span><span class="badge-lbl">vulns</span></span>
        <span class="badge-expl" hidden><span class="badge-num">0</span><span class="badge-lbl">exploits</span></span>
        <span class="badge-risk" hidden><span class="badge-num">0</span><span class="badge-lbl">risco</span></span>
      </span>
    </div>
    <div class="device-os" hidden></div>
    <div class="device-detail"></div>`;
  node.querySelector('.device-ip').textContent = ip;
  if (ip.includes(':')) node.querySelector('.device-ip').classList.add('v6');
  node.tabIndex = 0;
  node.setAttribute('role', 'button');
  node.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target === node) { e.preventDefault(); node.classList.toggle('open'); }
  });
  node.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) { if (!e.target.closest('.device-detail')) node.classList.toggle('open'); return; }
    e.stopPropagation();
    deviceAction(ip, btn);
  });
  els.devices.appendChild(node);
  els.devices.hidden = false;
  els.toolbar.hidden = false;
  els.empty.hidden = true;
  return node;
}

function renderDevice(h) {
  const node = deviceNode(h.ip);
  const alias = aliases[aliasKey(h)];
  node.querySelector('.device-name').textContent = alias
    ? alias + (h.hostname || h.vendor ? ` (${h.hostname || h.vendor})` : '')
    : (h.hostname || h.vendor || '');

  const osEl = node.querySelector('.device-os');
  if (h.os && h.os.name) {
    osEl.textContent = 'SO estimado: ' + h.os.name + (h.os.accuracy ? ` (${h.os.accuracy}%)` : '');
    osEl.hidden = false;
  } else { osEl.hidden = true; }

  const ports = h.ports || [], vulns = h.vulns || [];
  node.querySelector('.badge-ports .badge-num').textContent = ports.length;
  node.querySelector('.badge-vuln .badge-num').textContent = vulns.length;
  node.classList.toggle('clean', !vulns.length);
  const typeEl = node.querySelector('.device-type');
  typeEl.hidden = !h.type_label;
  typeEl.textContent = (h.type_label || '') + (h.trusted ? ' · confiável' : '');
  const riskEl = node.querySelector('.badge-risk');
  riskEl.hidden = h.risk == null;
  riskEl.className = 'badge-risk lvl-' + (h.risk_level || 'none');
  riskEl.querySelector('.badge-num').textContent = h.risk == null ? '' : h.risk;
  riskEl.title = h.risk_label ? `risco ${h.risk_label}` : '';
  node.dataset.risk = h.risk || 0;
  const nExpl = ports.reduce((a, p) => a + (p.exploits || []).length, 0);
  node.querySelector('.badge-expl .badge-num').textContent = nExpl;
  node.querySelector('.badge-expl').hidden = !nExpl;

  // pontinhos de severidade (mais graves presentes)
  const sevdots = node.querySelector('.device-sevdots');
  const present = new Set(vulns.map((v) => v.severity || 'info'));
  sevdots.innerHTML = '<span class="sev-dots">' +
    SEV.filter((s) => s !== 'info' && present.has(s)).map((s) => `<span class="sev-dot c-${s}"></span>`).join('') +
    '</span>';

  const detail = node.querySelector('.device-detail');
  const meta = [];
  if (h.mac) meta.push('MAC ' + h.mac);
  if (h.vendor) meta.push(h.vendor);
  if (h.first_seen) meta.push(`visto desde ${h.first_seen.slice(0, 16)} (${h.seen_count}x)`);
  if (h.ipv6 && h.ipv6.length) meta.push('IPv6 ' + h.ipv6.join(', '));
  const hi = h.host_info || {};
  if (hi['smb-os-discovery'] && !(h.os && h.os.name)) meta.push('SO ' + hi['smb-os-discovery']);
  let html = meta.length ? `<div class="device-meta">${esc(meta.join('  ·  '))}</div>` : '';

  // ações do dispositivo
  html += `<input class="alias-input" type="text" maxlength="80" placeholder="Apelido / nota (ex.: TV da sala)" value="${esc(alias || '')}" />`;
  html += '<div class="dev-actions">' +
    `<button class="btn btn-ghost act-rescan" data-act="rescan"${state.running ? ' disabled' : ''}>Re-escanear</button>` +
    '<button class="btn btn-ghost" data-act="copy">Copiar IP</button>' +
    '<button class="btn btn-ghost" data-act="copyjson">Copiar JSON</button>' +
    (h.inv_key ? `<button class="btn btn-ghost" data-act="trust">${h.trusted ? 'Deixar de confiar' : 'Confiar neste aparelho'}</button>` : '');
  for (const p of ports.filter(isWeb)) {
    const tls = isTls(p);
    html += `<button class="btn btn-ghost" data-act="web" data-port="${esc(p.port)}" data-tls="${tls ? 1 : ''}">Abrir ${tls ? 'https' : 'http'}:${esc(p.port)}</button>`;
  }
  html += '</div>';

  if (ports.length) {
    html += '<div class="ports">';
    for (const p of ports) {
      const ver = [p.product, p.version].filter(Boolean).join(' ');
      html += `<div class="port"><span class="port-id">${esc(p.port)}/${esc(p.proto)}</span> <span class="port-svc">${esc(p.service || '?')}</span>${p.ipv6 ? ' <span class="port-v6">só IPv6</span>' : ''}${ver ? `<span class="port-ver">${esc(ver)}</span>` : ''}${portInfo(p)}</div>`;
    }
    html += '</div>';
  }

  const withExpl = ports.filter((p) => (p.exploits || []).length);
  if (withExpl.length) {
    html += '<div class="expls"><div class="expls-title">Exploits públicos conhecidos (Exploit-DB) — confirme a versão antes de concluir</div>';
    for (const p of withExpl) {
      for (const x of p.exploits) {
        html += `<div class="expl"><span class="port-id">${esc(p.port)}/${esc(p.proto)}</span> ` +
          `<button class="btn btn-ghost expl-id" data-act="edb" data-id="${esc(x.id)}">EDB-${esc(x.id)}</button> ` +
          `<span>${esc(x.title)}</span>${x.type ? ` <span class="expl-type">${esc(x.type)}</span>` : ''}</div>`;
      }
    }
    html += '</div>';
  }

  if (vulns.length) {
    html += '<div class="vulns">';
    for (const v of vulns) {
      const sev = v.severity || 'info';
      const cvss = v.cvss ? `<span class="vuln-cvss">CVSS ${esc(v.cvss)}</span>` : '';
      const cves = (v.cves && v.cves.length) ? `<span class="vuln-cves">${esc(v.cves.slice(0, 8).join(', '))}</span>` : '';
      html += `<div class="vuln c-${sev}">
        <div class="vuln-top"><span class="sev-tag c-${sev}">${esc(sev.toUpperCase())}</span>${cvss}
          <span class="vuln-id">porta ${esc(v.port)} · ${esc(v.id)}${v.title ? ' — ' + esc(v.title) : ''}</span></div>
        ${vulnChips(v)}
        ${cves ? `<div class="vuln-cvewrap">${cves}</div>` : ''}
        ${(v.notes || []).map((n) => `<div class="vuln-note">${esc(n)}</div>`).join('')}
        ${v.fix ? `<div class="vuln-fix"><b>Correção:</b> ${esc(v.fix)}</div>` : ''}
        <div class="vuln-out">${esc(v.output)}</div></div>`;
    }
    html += '</div>';
  } else if (ports.length) {
    html += '<div class="no-vuln">Nenhuma vulnerabilidade sinalizada pelos scripts.</div>';
  }
  detail.innerHTML = html;
  node.dataset.search = [alias, h.type_label, h.ip, h.hostname, h.vendor, h.mac, h.os && h.os.name,
    ...ports.map((p) => `${p.port} ${p.service} ${p.product} ${Object.values(p.scripts || {}).join(' ')} ${(p.exploits || []).map((x) => `edb-${x.id} ${x.title} ${x.cves.join(' ')}`).join(' ')}`),
    ...(h.ipv6 || []), ...vulns.map((v) => `${v.id} ${v.title || ''} ${(v.cves || []).join(' ')}`)].filter(Boolean).join(' ').toLowerCase();
  applyFilter();
}

// título HTTP, servidor etc. coletados pelas checagens adaptativas
const INFO_LABEL = { 'http-title': 'título', 'http-server-header': 'servidor', 'ssh-auth-methods': 'login',
  'rdp-ntlm-info': 'RDP', 'mysql-info': 'MySQL', 'ftp-syst': 'sistema', 'ntp-info': 'NTP', 'rtsp-methods': 'RTSP' };
function portInfo(p) {
  const rows = Object.entries(p.scripts || {}).filter(([id]) => INFO_LABEL[id]);
  return rows.map(([id, out]) => `<span class="port-info"><b>${esc(INFO_LABEL[id])}:</b> ${esc(out)}</span>`).join('');
}

const CONF_LABEL = { high: 'confiança alta', medium: 'confiança média', low: 'confiança baixa' };
function vulnChips(v) {
  const chips = [];
  if (v.score != null) chips.push(`<span class="chip chip-score">nota ${esc(v.score)}</span>`);
  if (v.kev && v.kev.length) chips.push(`<span class="chip chip-kev" title="${esc(v.kev.join(', '))}">explorada ativamente (KEV)${v.ransomware ? ' · ransomware' : ''}</span>`);
  if (v.epss) chips.push(`<span class="chip">EPSS ${Math.round(v.epss * 100)}%</span>`);
  if (v.confidence) chips.push(`<span class="chip chip-conf-${esc(v.confidence)}">${CONF_LABEL[v.confidence] || esc(v.confidence)}</span>`);
  return chips.length ? `<div class="chips">${chips.join('')}</div>` : '';
}

const ALERT_LABEL = { critical: 'CRÍTICO', high: 'ALTO', medium: 'MÉDIO', low: 'BAIXO' };
function renderAnalysis(an, alerts) {
  els.analysis.hidden = !an;
  if (!an) return;
  alerts = alerts || [];
  els.anAlerts.hidden = !alerts.length;
  els.anAlerts.innerHTML = alerts.map((a) =>
    `<li class="an-alert"><span class="sev-tag c-${esc(a.level)}">${esc(ALERT_LABEL[a.level] || a.level)}</span> ${esc(a.text)}</li>`).join('');
  els.anRisk.textContent = an.risk;
  els.anRisk.className = 'an-risk lvl-' + an.level;
  els.anLevel.textContent = an.label.toUpperCase();
  els.anLevel.className = 'an-level lvl-' + an.level;
  els.anSummary.innerHTML = an.summary.map((s) => `<li>${esc(s)}</li>`).join('');
  els.anTopWrap.hidden = !an.top.length;
  els.anTop.innerHTML = an.top.map((t) => `<li><button class="an-item" data-ip="${esc(t.ip)}">
      <span class="an-score lvl-${t.score >= 80 ? 'critical' : t.score >= 60 ? 'high' : t.score >= 35 ? 'medium' : 'low'}">${esc(t.score)}</span>
      <span class="an-body"><b>${esc(t.title)}</b> <span class="an-where">${esc(t.ip)} · ${esc(t.type || '')} · porta ${esc(t.port)}</span>
      ${t.reasons.length ? `<span class="an-why">${esc(t.reasons.join(' · '))}</span>` : ''}
      ${t.fix ? `<span class="an-fix">${esc(t.fix)}</span>` : ''}</span></button></li>`).join('');
}

// mais arriscados primeiro
function sortDevices() {
  [...els.devices.children]
    .sort((a, b) => (+b.dataset.risk || 0) - (+a.dataset.risk || 0))
    .forEach((n) => els.devices.appendChild(n));
}

function isWeb(p) {
  return p.proto === 'tcp' && (/http/.test(p.service || '') || ['80', '443', '8000', '8080', '8443'].includes(String(p.port)));
}
function isTls(p) {
  return p.tunnel === 'ssl' || /https/.test(p.service || '') || ['443', '8443'].includes(String(p.port));
}

function applyFilter() {
  const q = els.filter.value.trim().toLowerCase();
  const only = els.onlyVuln.checked;
  let shown = 0;
  for (const node of els.devices.children) {
    const h = state.hosts.get(node.querySelector('.device-ip').textContent) || {};
    const hit = (!q || (node.dataset.search || '').includes(q)) && (!only || (h.vulns || []).length > 0);
    node.hidden = !hit;
    if (hit) shown++;
  }
  els.noMatch.hidden = shown > 0 || !els.devices.children.length;
}

// barra fina sob o topo: indeterminada na descoberta, proporcional na análise
function setProgress(mode, frac) {
  els.progress.hidden = mode === 'off';
  els.progress.classList.toggle('indeterminate', mode === 'busy');
  els.progressFill.style.width = mode === 'value' ? `${Math.round(frac * 100)}%` : '';
}

function copy(text, what) {
  navigator.clipboard.writeText(text)
    .then(() => logLine(`[+] ${what} copiado.`, 'ln-accent'))
    .catch(() => logLine('[!] Não consegui copiar para a área de transferência.', 'ln-danger'));
}

function deviceAction(ip, btn) {
  const h = state.hosts.get(ip) || { ip };
  switch (btn.dataset.act) {
    case 'copy': copy(ip, 'IP'); break;
    case 'trust':
      window.netscan.trust(h.inv_key, !h.trusted).then((res) => {
        if (!res || !res.ok) { logLine('[!] ' + ((res && res.error) || 'Não consegui atualizar o inventário.'), 'ln-danger'); return; }
        h.trusted = !h.trusted;
        logLine(`[+] ${ip} ${h.trusted ? 'marcado como confiável: não gera mais alerta de aparelho desconhecido' : 'não é mais confiável'}.`, 'ln-accent');
        renderDevice(h);
      });
      break;
    case 'copyjson': copy(JSON.stringify(h, null, 2), 'JSON do dispositivo'); break;
    case 'edb': window.netscan.openEdb(btn.dataset.id); break;
    case 'web': window.netscan.openWeb(ip, btn.dataset.port, !!btn.dataset.tls); break;
    case 'rescan':
      if (state.running) return;
      // mantém os outros dispositivos na tela; só este host é varrido de novo (sem comparação)
      startScan({ ...currentOpts(), target: ip, exclude: null, compare: '', repeat: 0, single: true }, true);
      break;
  }
}

function markDiff(diff) {
  if (!diff) return;
  const tag = (ip, text, cls) => {
    const node = document.getElementById('dev-' + cssId(ip));
    if (!node) return;
    const name = node.querySelector('.device-name');
    const old = name.querySelector('.diff-tag');
    if (old) old.remove();
    const t = document.createElement('span');
    t.className = 'diff-tag ' + cls;
    t.textContent = text;
    name.appendChild(t);
  };
  for (const ip of diff.new_hosts) tag(ip, 'novo', 'diff-new');
  for (const [ip, d] of Object.entries(diff.changed)) {
    tag(ip, 'mudou', d.new_vulns.length ? 'diff-bad' : 'diff-chg');
    const parts = [];
    if (d.new_ports.length) parts.push('portas novas ' + d.new_ports.join(', '));
    if (d.closed_ports.length) parts.push('fechadas ' + d.closed_ports.join(', '));
    if (d.new_vulns.length) parts.push('vulns novas ' + d.new_vulns.join(', '));
    if (d.fixed_vulns.length) parts.push('corrigidas ' + d.fixed_vulns.join(', '));
    logLine(`[~] ${ip}: ${parts.join('; ')}`);
  }
  for (const ip of diff.gone_hosts) logLine(`[~] ${ip} não respondeu desta vez (estava na varredura anterior).`);
  logLine(`[+] Comparação: ${diff.new_hosts.length} novo(s), ${diff.gone_hosts.length} sumido(s), ` +
    `${Object.keys(diff.changed).length} alterado(s).`, 'ln-accent');
}

function resetResults() {
  state.hosts.clear();
  state.outdir = null;
  els.devices.innerHTML = '';
  els.devices.hidden = true;
  els.toolbar.hidden = true;
  els.noMatch.hidden = true;
  els.analysis.hidden = true;
  els.empty.hidden = false;
  els.emptyBig.textContent = 'Varrendo a rede…';
  els.emptySub.textContent = 'Os dispositivos aparecem aqui conforme são encontrados.';
  els.log.innerHTML = '';
  els.report.hidden = true;
  recount();
}

// ---- password modal ----

function showPwModal(reset) {
  if (reset) els.pwInput.value = '';
  els.pwError.hidden = true;
  els.pwOverlay.hidden = false;
  setTimeout(() => els.pwInput.focus(), 30);
}
function hidePwModal() {
  els.pwOverlay.hidden = true;
  els.pwInput.value = '';
}

els.pwForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = els.pwInput.value;
  if (!pw) { els.pwError.textContent = 'Digite a senha.'; els.pwError.hidden = false; return; }
  els.pwError.hidden = true;
  logLine('[*] Autenticando sudo…');
  const res = await window.netscan.startSudo(state.pendingOpts, pw);
  if (res && res.ok) {
    hidePwModal();
    // scan iniciou
  } else if (res && res.badPassword) {
    els.pwError.textContent = 'Senha incorreta. Tente novamente.';
    els.pwError.hidden = false;
    els.pwInput.value = '';
    els.pwInput.focus();
  } else {
    hidePwModal();
    logLine('[!] ' + (res && res.error ? res.error : 'Falha ao autenticar.'), 'ln-danger');
    setRunning(false);
    els.barPhase.textContent = 'erro';
  }
});

els.pwCancel.addEventListener('click', () => {
  hidePwModal();
  logLine('[!] Varredura cancelada (sem senha).', 'ln-danger');
  setRunning(false);
  els.barPhase.textContent = 'cancelado';
});

// ---- events from main ----

window.netscan.onEvent((evt) => {
  switch (evt.event) {
    case 'start':
      // varredura iniciada em outra aba ou pelo agendamento do servidor: mostra do zero
      if (!state.running) { resetResults(); setRunning(true); }
      state.outdir = evt.outdir;
      els.barTarget.textContent = evt.target + (evt.deep ? ' · profunda' : '') + (evt.root ? ' · root' : '');
      break;
    case 'service':
      logLine(evt.action === 'install' ? `[+] Monitoramento ativado: a cada ${evt.every} min, mesmo com o app fechado.`
        : '[+] Monitoramento em segundo plano desativado.', 'ln-accent');
      els.barPhase.textContent = evt.action === 'install' ? 'serviço ativado' : 'serviço desativado';
      refreshService();
      refreshHistory();
      break;
    case 'phase':
      setProgress(evt.phase === 'discovery' ? 'busy' : 'value', 0);
      els.barPhase.textContent = evt.phase === 'discovery' ? 'descobrindo' : 'varrendo';
      break;
    case 'discovery':
      for (const h of evt.hosts) { state.hosts.set(h.ip, h); renderDevice(h); }
      recount();
      break;
    case 'host_start': {
      const node = deviceNode(evt.ip);
      node.classList.add('scanning');
      els.barPhase.textContent = `varrendo ${evt.index}/${evt.total}`;
      break;
    }
    case 'host_progress': {
      const node = deviceNode(evt.ip);
      node.querySelector('.device-prog').textContent =
        `${evt.phase} ${Math.round(evt.pct)}%` + (evt.eta ? ` · resta ${evt.eta}` : '');
      break;
    }
    case 'host_done': {
      const h = evt.host;
      state.hosts.set(h.ip, h);
      renderDevice(h);
      const node = deviceNode(h.ip);
      node.classList.remove('scanning');
      node.querySelector('.device-prog').textContent = '';
      setProgress('value', evt.index / evt.total);
      if ((h.vulns || []).length) node.classList.add('open');
      recount();
      break;
    }
    case 'done':
      els.barPhase.textContent = 'concluído';
      setRunning(false);
      setProgress('off');
      if (!state.hosts.size) {
        els.emptyBig.textContent = 'Nenhum dispositivo encontrado.';
        els.emptySub.textContent = 'Confira o alvo, tente com sudo ou marque "Sem ping" nas opções avançadas.';
      }
      // dados finais (inventário, análise) só existem no fim: redesenha com eles
      for (const h of evt.hosts || []) { state.hosts.set(h.ip, h); renderDevice(h); }
      recount();
      markDiff(evt.diff);
      if (evt.analysis && !(state.pendingOpts || {}).single) renderAnalysis(evt.analysis, evt.alerts);
      notifyAlerts(evt.alerts);
      sortDevices();
      refreshHistory();
      scheduleNext();
      if (state.outdir) {
        els.reportText.textContent = `Relatório salvo em ${state.outdir}`;
        els.report.hidden = false;
      }
      break;
    case 'aborted':
      els.barPhase.textContent = 'interrompido';
      setRunning(false);
      setProgress('off');
      scheduleNext();
      break;
    case 'fatal':
      logLine('[!] ' + (evt.error || 'Erro fatal.'), 'ln-danger');
      els.barPhase.textContent = 'erro';
      setRunning(false);
      setProgress('off');
      break;
  }
});

window.netscan.onLog((line) => {
  let cls = '';
  if (line.startsWith('[+]')) cls = 'ln-accent';
  else if (line.startsWith('[!]')) cls = 'ln-danger';
  logLine(line, cls);
});

window.netscan.onError((msg) => {
  logLine('[!] ' + msg, 'ln-danger');
  if (/ENOENT/.test(msg)) logLine('[!] Comando não encontrado (python3/sudo/nmap ausente?).', 'ln-danger');
  setRunning(false);
  els.barPhase.textContent = 'erro';
});

window.netscan.onClose((info) => {
  if (info.code !== 0 && info.code !== null && info.code !== 130) {
    logLine(`[!] Processo encerrou com código ${info.code}.`, 'ln-danger');
  }
  setRunning(false);
});

// ---- UI actions ----

async function startScan(opts, keep) {
  if (keep) { els.report.hidden = true; } else { resetResults(); }
  setRunning(true);
  els.barPhase.textContent = 'iniciando';
  state.pendingOpts = opts;
  const res = await window.netscan.start(opts);
  if (res && res.ok) return;                 // rodando
  if (res && res.needPassword) {             // precisa de senha
    els.barPhase.textContent = 'aguardando senha';
    showPwModal(true);
    return;
  }
  logLine('[!] ' + (res && res.error ? res.error : 'Falha ao iniciar.'), 'ln-danger');
  setRunning(false);
  els.barPhase.textContent = 'erro';
}

els.start.addEventListener('click', () => {
  state.monitorOff = false;
  state.lastOpts = currentOpts();
  startScan(state.lastOpts, false);
});

// ---- monitoramento ----

function scheduleNext() {
  const opts = state.lastOpts;
  if (!opts || !opts.repeat || state.monitorOff || (state.pendingOpts || {}).single) return;
  const ms = opts.repeat * 60000;
  const at = new Date(Date.now() + ms).toLocaleTimeString().slice(0, 5);
  els.barPhase.textContent = `próxima às ${at}`;
  logLine(`[~] Monitorando: próxima varredura às ${at}.`);
  state.monitorTimer = setTimeout(() => {
    state.monitorTimer = null;
    startScan({ ...opts, compare: 'latest' }, false);
  }, ms);
  els.stop.disabled = false;
}

function notifyAlerts(alerts) {
  if (!alerts || !alerts.length || (settings && settings.integrations.desktop === false)) return;
  const body = alerts.slice(0, 3).map((a) => a.text).join('\n') + (alerts.length > 3 ? `\n+${alerts.length - 3} alerta(s)` : '');
  try { new Notification(`netscan — ${alerts.length} alerta(s)`, { body }); } catch (_) {}
}

// ---- serviço em segundo plano (systemd) ----

async function refreshService() {
  const s = await window.netscan.serviceStatus();
  els.svcRemove.hidden = !(s && s.installed);
  els.svcInstall.textContent = s && s.installed ? 'Atualizar' : 'Ativar';
  if (!s || !s.available) els.svcStatus.textContent = 'systemd indisponível neste sistema.';
  else if (!s.installed) els.svcStatus.textContent = 'Desativado.';
  else els.svcStatus.textContent = (s.active ? 'Ativo' : 'Instalado, parado') + (s.next ? ` · próxima: ${s.next}` : '');
  els.svcStatus.classList.toggle('svc-on', !!(s && s.active));
}

function serviceAction(action) {
  if (state.running) return;
  const every = Math.min(10080, Math.max(5, parseInt(els.svcEvery.value, 10) || 60));
  // pede sudo sempre: instalar/remover unidades do systemd exige root
  startScan({ ...currentOpts(), useSudo: true, compare: '', repeat: 0, serviceAction: action, every }, true);
}
els.svcInstall.addEventListener('click', () => serviceAction('install'));
els.svcRemove.addEventListener('click', () => serviceAction('uninstall'));

// ---- histórico ----

async function refreshHistory() {
  const list = await window.netscan.historyList();
  const keep = els.compare.value;
  els.compare.innerHTML = '<option value="latest">a varredura anterior</option><option value="">não comparar</option>' +
    list.map((r) => `<option value="${esc(r.name)}">${esc(r.timestamp)} · ${esc(r.target)}</option>`).join('');
  els.compare.value = [...els.compare.options].some((o) => o.value === keep) ? keep : 'latest';
  if (!list.length) return;
  els.history.innerHTML = list.map((r) => {
    const bad = (r.totals.critical || 0) + (r.totals.high || 0);
    return `<li><button class="history-item" data-name="${esc(r.name)}">` +
      `<span class="history-ts">${esc(r.timestamp)}</span>` +
      `<span class="history-meta">${r.service ? '<i>serviço</i> · ' : ''}${esc(r.target)} · ${r.hosts} disp.` +
      `${r.risk != null ? ` · risco ${r.risk}` : ''}${bad ? ` · <b>${bad} graves</b>` : ''}${r.alerts ? ` · <b>${r.alerts} alerta(s)</b>` : ''}</span></button></li>`;
  }).join('');
}

els.history.addEventListener('click', async (e) => {
  const btn = e.target.closest('.history-item');
  if (!btn || state.running) return;
  const res = await window.netscan.historyLoad(btn.dataset.name);
  if (!res || !res.ok) { logLine('[!] ' + ((res && res.error) || 'Falha ao abrir.'), 'ln-danger'); return; }
  resetResults();
  const r = res.report;
  state.outdir = res.outdir;
  els.barTarget.textContent = r.target;
  els.barPhase.textContent = 'histórico ' + r.timestamp;
  for (const h of r.hosts || []) { state.hosts.set(h.ip, h); renderDevice(h); }
  recount();
  markDiff(r.diff);
  renderAnalysis(r.analysis, r.alerts);
  sortDevices();
  els.reportText.textContent = `Relatório de ${r.timestamp} em ${res.outdir}`;
  els.report.hidden = false;
});

els.devices.addEventListener('change', (e) => {
  if (!e.target.classList.contains('alias-input')) return;
  const ip = e.target.closest('.device').querySelector('.device-ip').textContent;
  const h = state.hosts.get(ip);
  if (!h) return;
  saveAlias(h, e.target.value.trim());
  renderDevice(h);
});

recount();
refreshHistory();
initPlatform();

els.stop.addEventListener('click', async () => {
  state.monitorOff = true;
  window.netscan.monitorStop();
  if (state.monitorTimer) {
    clearTimeout(state.monitorTimer);
    state.monitorTimer = null;
    els.stop.disabled = !state.running;
    els.barPhase.textContent = 'monitoramento parado';
    logLine('[~] Monitoramento parado.');
    if (!state.running) return;
  }
  await window.netscan.stop();
  logLine('[!] Parando varredura…', 'ln-danger');
  els.barPhase.textContent = 'parando';
});

els.openReport.addEventListener('click', () => {
  if (state.outdir) window.netscan.openPath(state.outdir);
});
els.downloadCsv.addEventListener('click', () => {
  if (state.outdir) window.netscan.openPath(state.outdir + '/relatorio.csv');
});

els.openHtml.addEventListener('click', () => {
  if (state.outdir) window.netscan.openPath(state.outdir + '/relatorio.html');
});

els.exportPdf.addEventListener('click', async () => {
  if (!state.outdir) return;
  els.exportPdf.disabled = true;
  logLine('[*] Gerando PDF…');
  const res = await window.netscan.exportPdf(state.outdir);
  els.exportPdf.disabled = false;
  logLine(res && res.ok ? `[+] ${res.message || `PDF salvo em ${res.path}`}` : '[!] ' + ((res && res.error) || 'Falha ao gerar o PDF.'),
    res && res.ok ? 'ln-accent' : 'ln-danger');
});
els.filter.addEventListener('input', applyFilter);
els.anTop.addEventListener('click', (e) => {
  const b = e.target.closest('.an-item');
  if (!b) return;
  const node = document.getElementById('dev-' + cssId(b.dataset.ip));
  if (!node) return;
  els.filter.value = ''; els.onlyVuln.checked = false; applyFilter();
  node.classList.add('open');
  node.scrollIntoView({ behavior: 'smooth', block: 'start' });
  node.focus({ preventScroll: true });
});
els.clearLog.addEventListener('click', () => { els.log.innerHTML = ''; });
els.target.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !state.running) els.start.click(); });
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !els.pwOverlay.hidden) els.pwCancel.click();
  else if (e.key === 'Escape' && !els.prefsOverlay.hidden) closePrefs();
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && !els.toolbar.hidden) { e.preventDefault(); els.filter.focus(); }
});
els.onlyVuln.addEventListener('change', applyFilter);
els.expandAll.addEventListener('click', () => {
  const nodes = [...els.devices.children].filter((n) => !n.hidden);
  const open = nodes.some((n) => !n.classList.contains('open'));
  nodes.forEach((n) => n.classList.toggle('open', open));
});


// ---- preferências (salvas em settings.json pelo processo principal/servidor) ----

const MODE_HINT = {
  fast: 'Só portas e serviços — inventário em segundos por aparelho.',
  normal: 'Serviços + checagens de vulnerabilidade escolhidas por serviço.',
  deep: 'Todas as 65.535 portas e checagens extras — bem mais lento.',
};
let settings = null;
let saveTimer = null;

function fillPrefs(s) {
  const sc = s.scan, it = s.integrations;
  els.target.value = sc.target || '';
  (modeInputs().find((i) => i.value === sc.mode) || $('modeNormal')).checked = true;
  els.modeHint.textContent = MODE_HINT[currentMode()];
  els.sudo.checked = sc.useSudo;
  els.ports.value = sc.ports; els.exclude.value = sc.exclude; els.workers.value = sc.workers;
  els.udp.checked = sc.udp; els.noPing.checked = sc.noPing; els.ipv6.checked = sc.ipv6;
  els.defaultCreds.checked = sc.defaultCreds;
  if ([...els.compare.options].some((o) => o.value === sc.compare)) els.compare.value = sc.compare;
  els.schedEvery.value = s.schedule.every;
  els.webhook.value = it.webhook; els.tgChat.value = it.telegram_chat; els.minLevel.value = it.min_level;
  els.desktopNotify.checked = it.desktop;
  // o servidor nunca devolve o token: só diz se há um salvo
  els.tgToken.value = it.telegram_token || '';
  els.tgToken.placeholder = it.telegram_token_set ? 'salvo — digite para trocar' : '123456:ABC…';
}

function collectPrefs() {
  return {
    scan: {
      target: els.target.value.trim(), mode: currentMode(), useSudo: els.sudo.checked,
      ports: els.ports.value.trim(), exclude: els.exclude.value.trim(),
      workers: Math.min(16, Math.max(1, parseInt(els.workers.value, 10) || 1)),
      udp: els.udp.checked, noPing: els.noPing.checked, ipv6: els.ipv6.checked,
      defaultCreds: els.defaultCreds.checked, compare: els.compare.value,
    },
    schedule: { every: Math.min(10080, Math.max(0, parseInt(els.schedEvery.value, 10) || 0)) },
    integrations: {
      webhook: els.webhook.value.trim(), telegram_token: els.tgToken.value.trim(),
      telegram_chat: els.tgChat.value.trim(), min_level: els.minLevel.value, desktop: els.desktopNotify.checked,
    },
  };
}

function savePrefs() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    const data = collectPrefs();
    if (data.schedule.every > 0 && data.schedule.every < 5) data.schedule.every = 5;
    const res = await window.netscan.saveSettings(data);
    if (res && res.ok) { settings = res.settings; refreshSchedule(); }
    else logLine('[!] Não consegui salvar as preferências: ' + ((res && res.error) || 'erro'), 'ln-danger');
  }, 400);
}

function openPrefs(tab) {
  els.prefsOverlay.hidden = false;
  selectTab(tab || 'scan');
  refreshSchedule();
}
function closePrefs() { els.prefsOverlay.hidden = true; els.prefsBtn.focus(); }
function selectTab(name) {
  document.querySelectorAll('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.tab === name)));
  document.querySelectorAll('.tab-panel').forEach((p) => { p.hidden = p.dataset.panel !== name; });
}

async function refreshSchedule() {
  if (window.netscan.platform === 'web') {
    const info = await window.netscan.info();
    const sch = info && info.scheduler;
    els.schedStatus.textContent = sch && sch.every ? `Ativo: a cada ${sch.every} min` + (sch.next ? ` · próxima às ${sch.next}` : '') : 'Desligado.';
    els.schedStatus.classList.toggle('svc-on', !!(sch && sch.every));
  } else {
    refreshService();
  }
}

async function initPlatform() {
  document.body.dataset.platform = window.netscan.platform || 'electron';
  try { settings = await window.netscan.getSettings(); } catch (_) { settings = null; }
  if (settings) fillPrefs(settings);
  refreshSchedule();
}

els.prefsBtn.addEventListener('click', () => openPrefs());
els.prefsClose.addEventListener('click', closePrefs);
els.prefsOverlay.addEventListener('click', (e) => { if (e.target === els.prefsOverlay) closePrefs(); });
document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => selectTab(t.dataset.tab)));
els.prefsOverlay.addEventListener('change', savePrefs);
els.prefsOverlay.addEventListener('input', (e) => { if (e.target.matches('input[type=text], input[type=url], input[type=password], input[type=number]')) savePrefs(); });
els.target.addEventListener('change', savePrefs);
modeInputs().forEach((i) => i.addEventListener('change', () => { els.modeHint.textContent = MODE_HINT[currentMode()]; savePrefs(); }));
els.logoutBtn.addEventListener('click', () => window.netscan.logout());

els.testNotify.addEventListener('click', async () => {
  clearTimeout(saveTimer);
  await window.netscan.saveSettings(collectPrefs()); // testa o que está na tela
  els.testNotify.disabled = true;
  els.testResult.textContent = 'Enviando…';
  const res = await window.netscan.testNotify();
  els.testNotify.disabled = false;
  if (res && res.sent && res.sent.length) els.testResult.textContent = `Enviado por: ${res.sent.join(', ')}.`;
  else if (res && res.errors && res.errors.length) els.testResult.textContent = res.errors.join(' · ');
  else els.testResult.textContent = 'Nenhuma integração configurada.';
});
