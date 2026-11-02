'use strict';

const $ = (id) => document.getElementById(id);

const els = {
  target: $('target'), fast: $('fast'), deep: $('deep'), sudo: $('sudo'),
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

let state = { hosts: new Map(), outdir: null, running: false, pendingOpts: null };

function currentOpts() {
  return {
    target: els.target.value.trim() || null,
    fast: els.fast.checked,
    deep: els.deep.checked,
    useSudo: els.sudo.checked,
  };
}

function setRunning(on) {
  state.running = on;
  for (const el of [els.start]) el.disabled = on;
  els.stop.disabled = !on;
  for (const el of [els.target, els.fast, els.deep, els.sudo]) el.disabled = on;
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
      <span class="device-badges">
        <span class="device-sevdots"></span>
        <span class="badge-ports"><span class="badge-num">0</span><span class="badge-lbl">portas</span></span>
        <span class="badge-vuln"><span class="badge-num">0</span><span class="badge-lbl">vulns</span></span>
      </span>
    </div>
    <div class="device-os" hidden></div>
    <div class="device-detail"></div>`;
  node.querySelector('.device-ip').textContent = ip;
  node.addEventListener('click', () => node.classList.toggle('open'));
  els.devices.appendChild(node);
  els.devices.hidden = false;
  els.empty.hidden = true;
  return node;
}

function renderDevice(h) {
  const node = deviceNode(h.ip);
  node.querySelector('.device-name').textContent = h.hostname || h.vendor || '';

  const osEl = node.querySelector('.device-os');
  if (h.os && h.os.name) {
    osEl.textContent = 'SO estimado: ' + h.os.name + (h.os.accuracy ? ` (${h.os.accuracy}%)` : '');
    osEl.hidden = false;
  } else { osEl.hidden = true; }

  const ports = h.ports || [], vulns = h.vulns || [];
  node.querySelector('.badge-ports .badge-num').textContent = ports.length;
  node.querySelector('.badge-vuln .badge-num').textContent = vulns.length;

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
  let html = meta.length ? `<div class="device-meta">${esc(meta.join('  ·  '))}</div>` : '';

  if (ports.length) {
    html += '<div class="ports">';
    for (const p of ports) {
      const ver = [p.product, p.version].filter(Boolean).join(' ');
      html += `<div class="port"><span class="port-id">${esc(p.port)}/${esc(p.proto)}</span> <span class="port-svc">${esc(p.service || '?')}</span>${ver ? `<span class="port-ver">${esc(ver)}</span>` : ''}</div>`;
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
          <span class="vuln-id">porta ${esc(v.port)} · ${esc(v.id)}</span></div>
        ${cves ? `<div style="margin-top:6px">${cves}</div>` : ''}
        <div class="vuln-out">${esc(v.output)}</div></div>`;
    }
    html += '</div>';
  } else if (ports.length) {
    html += '<div class="no-vuln">Nenhuma vulnerabilidade sinalizada pelos scripts.</div>';
  }
  detail.innerHTML = html;
}

function resetResults() {
  state.hosts.clear();
  state.outdir = null;
  els.devices.innerHTML = '';
  els.devices.hidden = true;
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
    case 'host_done': {
      const h = evt.host;
      state.hosts.set(h.ip, h);
      renderDevice(h);
      const node = deviceNode(h.ip);
      node.classList.remove('scanning');
      if ((h.vulns || []).length) node.classList.add('open');
      recount();
      break;
    }
    case 'done':
      els.barPhase.textContent = 'concluído';
      setRunning(false);
      if (state.outdir) {
        els.reportText.textContent = `Relatório salvo em ${state.outdir}`;
        els.report.hidden = false;
      }
      break;
    case 'aborted':
      els.barPhase.textContent = 'interrompido';
      setRunning(false);
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

els.start.addEventListener('click', async () => {
  resetResults();
  setRunning(true);
  els.barPhase.textContent = 'iniciando';
  const opts = currentOpts();
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
});

els.stop.addEventListener('click', async () => {
  await window.netscan.stop();
  logLine('[!] Parando varredura…', 'ln-danger');
  els.barPhase.textContent = 'parando';
});

els.openReport.addEventListener('click', () => {
  if (state.outdir) window.netscan.openPath(state.outdir);
});
