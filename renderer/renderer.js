'use strict';

const $ = (id) => document.getElementById(id);

const els = {
  target: $('target'), fast: $('fast'), deep: $('deep'), sudo: $('sudo'),
  ports: $('ports'), exclude: $('exclude'), workers: $('workers'),
  udp: $('udp'), noPing: $('noPing'), ipv6: $('ipv6'), compare: $('compare'),
  toolbar: $('toolbar'), filter: $('filter'), onlyVuln: $('onlyVuln'), expandAll: $('expandAll'),
  openHtml: $('openHtml'), repeat: $('repeat'), history: $('history'),
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

function currentOpts() {
  return {
    target: els.target.value.trim() || null,
    fast: els.fast.checked,
    deep: els.deep.checked,
    useSudo: els.sudo.checked,
    ports: els.ports.value.trim() || null,
    exclude: els.exclude.value.trim() || null,
    workers: els.workers.value,
    udp: els.udp.checked,
    noPing: els.noPing.checked,
    ipv6: els.ipv6.checked,
    compare: els.compare.value,
    repeat: Math.max(0, parseInt(els.repeat.value, 10) || 0),
  };
}

function setRunning(on) {
  state.running = on;
  for (const el of [els.start]) el.disabled = on;
  els.stop.disabled = !on;
  for (const el of [els.target, els.fast, els.deep, els.sudo, els.ports, els.exclude,
    els.workers, els.udp, els.noPing, els.ipv6, els.compare, els.repeat]) el.disabled = on;
  if (state.monitorTimer) els.stop.disabled = false; // permite parar o monitoramento na espera
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
      <span class="device-prog"></span>
      <span class="device-badges">
        <span class="device-sevdots"></span>
        <span class="badge-ports"><span class="badge-num">0</span><span class="badge-lbl">portas</span></span>
        <span class="badge-vuln"><span class="badge-num">0</span><span class="badge-lbl">vulns</span></span>
        <span class="badge-expl" hidden><span class="badge-num">0</span><span class="badge-lbl">exploits</span></span>
      </span>
    </div>
    <div class="device-os" hidden></div>
    <div class="device-detail"></div>`;
  node.querySelector('.device-ip').textContent = ip;
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
  if (h.ipv6 && h.ipv6.length) meta.push('IPv6 ' + h.ipv6.join(', '));
  let html = meta.length ? `<div class="device-meta">${esc(meta.join('  ·  '))}</div>` : '';

  // ações do dispositivo
  html += `<input class="alias-input" type="text" maxlength="80" placeholder="Apelido / nota (ex.: TV da sala)" value="${esc(alias || '')}" />`;
  html += '<div class="dev-actions">' +
    `<button class="btn btn-ghost act-rescan" data-act="rescan"${state.running ? ' disabled' : ''}>Re-escanear</button>` +
    '<button class="btn btn-ghost" data-act="copy">Copiar IP</button>' +
    '<button class="btn btn-ghost" data-act="copyjson">Copiar JSON</button>';
  for (const p of ports.filter(isWeb)) {
    const tls = isTls(p);
    html += `<button class="btn btn-ghost" data-act="web" data-port="${esc(p.port)}" data-tls="${tls ? 1 : ''}">Abrir ${tls ? 'https' : 'http'}:${esc(p.port)}</button>`;
  }
  html += '</div>';

  if (ports.length) {
    html += '<div class="ports">';
    for (const p of ports) {
      const ver = [p.product, p.version].filter(Boolean).join(' ');
      html += `<div class="port"><span class="port-id">${esc(p.port)}/${esc(p.proto)}</span> <span class="port-svc">${esc(p.service || '?')}</span>${p.ipv6 ? ' <span class="port-v6">só IPv6</span>' : ''}${ver ? `<span class="port-ver">${esc(ver)}</span>` : ''}</div>`;
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
        ${cves ? `<div class="vuln-cvewrap">${cves}</div>` : ''}
        ${v.fix ? `<div class="vuln-fix"><b>Correção:</b> ${esc(v.fix)}</div>` : ''}
        <div class="vuln-out">${esc(v.output)}</div></div>`;
    }
    html += '</div>';
  } else if (ports.length) {
    html += '<div class="no-vuln">Nenhuma vulnerabilidade sinalizada pelos scripts.</div>';
  }
  detail.innerHTML = html;
  node.dataset.search = [alias, h.ip, h.hostname, h.vendor, h.mac, h.os && h.os.name,
    ...ports.map((p) => `${p.port} ${p.service} ${p.product} ${(p.exploits || []).map((x) => `edb-${x.id} ${x.title} ${x.cves.join(' ')}`).join(' ')}`),
    ...(h.ipv6 || []), ...vulns.map((v) => `${v.id} ${v.title || ''} ${(v.cves || []).join(' ')}`)].filter(Boolean).join(' ').toLowerCase();
  applyFilter();
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
  for (const node of els.devices.children) {
    const h = state.hosts.get(node.querySelector('.device-ip').textContent) || {};
    const hit = (!q || (node.dataset.search || '').includes(q)) && (!only || (h.vulns || []).length > 0);
    node.hidden = !hit;
  }
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
  els.empty.hidden = false;
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
      state.outdir = evt.outdir;
      els.barTarget.textContent = evt.target + (evt.deep ? ' · profunda' : '') + (evt.root ? ' · root' : '');
      break;
    case 'phase':
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
      if ((h.vulns || []).length) node.classList.add('open');
      recount();
      break;
    }
    case 'done':
      els.barPhase.textContent = 'concluído';
      setRunning(false);
      markDiff(evt.diff);
      notifyDiff(evt.diff);
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
      scheduleNext();
      break;
    case 'fatal':
      logLine('[!] ' + (evt.error || 'Erro fatal.'), 'ln-danger');
      els.barPhase.textContent = 'erro';
      setRunning(false);
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

function notifyDiff(diff) {
  if (!diff) return;
  const newVulns = Object.values(diff.changed).reduce((a, d) => a + d.new_vulns.length, 0);
  if (!diff.new_hosts.length && !newVulns) return;
  const body = [diff.new_hosts.length && `${diff.new_hosts.length} dispositivo(s) novo(s): ${diff.new_hosts.join(', ')}`,
    newVulns && `${newVulns} vulnerabilidade(s) nova(s)`].filter(Boolean).join(' · ');
  try { new Notification('netscan — mudanças na rede', { body }); } catch (_) {}
}

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
      `<span class="history-meta">${esc(r.target)} · ${r.hosts} disp.${bad ? ` · <b>${bad} graves</b>` : ''}</span></button></li>`;
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

refreshHistory();

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

els.openHtml.addEventListener('click', () => {
  if (state.outdir) window.netscan.openPath(state.outdir + '/relatorio.html');
});

els.filter.addEventListener('input', applyFilter);
els.onlyVuln.addEventListener('change', applyFilter);
els.expandAll.addEventListener('click', () => {
  const nodes = [...els.devices.children].filter((n) => !n.hidden);
  const open = nodes.some((n) => !n.classList.contains('open'));
  nodes.forEach((n) => n.classList.toggle('open', open));
});
