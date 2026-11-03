'use strict';

// Versão web (Docker/Umbrel): implementa a mesma API que o preload do Electron expõe,
// usando HTTP + Server-Sent Events. No app desktop, window.netscan já existe e nada aqui roda.
if (!window.netscan) (() => {
  const HEADERS = { 'Content-Type': 'application/json', 'X-Netscan': '1' };
  const toLogin = () => { location.href = '/login.html'; };

  async function api(method, url, body) {
    const r = await fetch(url, {
      method, headers: HEADERS, credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (r.status === 401) { toLogin(); throw new Error('login necessário'); }
    return r.json();
  }

  // "/data/resultados_x" ou "/data/resultados_x/relatorio.csv" -> ["resultados_x", "relatorio.csv"]
  function reportRef(p) {
    const parts = String(p || '').split('/').filter(Boolean);
    const last = parts[parts.length - 1] || '';
    return /^relatorio\./.test(last) ? [parts[parts.length - 2], last] : [last, 'relatorio.html'];
  }
  const reportUrl = (dir, file) => `/api/report/${encodeURIComponent(dir)}/${encodeURIComponent(file)}`;

  const listeners = { event: [], log: [], error: [], close: [] };
  function connect() {
    const es = new EventSource('/api/events');
    es.onmessage = (m) => {
      let msg;
      try { msg = JSON.parse(m.data); } catch (_) { return; }
      (listeners[msg.type] || []).forEach((cb) => cb(msg.data));
    };
    es.onerror = async () => {
      // queda de conexão: o EventSource reconecta sozinho; só a sessão expirada exige login
      try {
        const r = await fetch('/api/info', { credentials: 'same-origin' });
        if (r.status === 401) { es.close(); toLogin(); }
      } catch (_) { /* servidor fora do ar: o navegador tenta de novo */ }
    };
  }

  window.netscan = {
    platform: 'web',
    start: (opts) => api('POST', '/api/scan/start', { opts }),
    startSudo: (opts) => api('POST', '/api/scan/start', { opts }),
    stop: () => api('POST', '/api/scan/stop', {}),
    monitorStop: async () => ({ ok: true }),
    historyList: () => api('GET', '/api/history'),
    historyLoad: (name) => api('GET', '/api/history/' + encodeURIComponent(name)),
    trust: (key, trusted) => api('POST', '/api/inventory/trust', { key, trusted }),
    serviceStatus: async () => ({ available: false }),
    info: () => api('GET', '/api/info'),
    getSettings: () => api('GET', '/api/settings'),
    saveSettings: (data) => api('POST', '/api/settings', data),
    testNotify: () => api('POST', '/api/notify/test', {}),
    logout: async () => { try { await api('POST', '/api/logout', {}); } finally { toLogin(); } },
    openPath: (p) => { const [dir, file] = reportRef(p); window.open(reportUrl(dir, file), '_blank', 'noopener'); },
    exportPdf: async (dir) => {
      // o navegador gera o PDF: abre o relatório e chama a impressão ("Salvar como PDF")
      const w = window.open(reportUrl(reportRef(dir)[0], 'relatorio.html'), '_blank');
      if (!w) return { ok: false, error: 'O navegador bloqueou a nova aba.' };
      w.addEventListener('load', () => w.print());
      return { ok: true, message: 'Relatório aberto — escolha "Salvar como PDF" na impressão.' };
    },
    openEdb: (id) => {
      if (/^\d{1,7}$/.test(String(id))) window.open(`https://www.exploit-db.com/exploits/${id}`, '_blank', 'noopener');
    },
    openWeb: (ip, port, tls) => {
      const n = parseInt(port, 10);
      if (!(n > 0 && n < 65536) || !/^[0-9a-f:.%]+$/i.test(String(ip))) return;
      const host = String(ip).includes(':') ? `[${ip}]` : ip;
      window.open(`${tls ? 'https' : 'http'}://${host}:${n}/`, '_blank', 'noopener');
    },
    onEvent: (cb) => listeners.event.push(cb),
    onLog: (cb) => listeners.log.push(cb),
    onError: (cb) => listeners.error.push(cb),
    onClose: (cb) => listeners.close.push(cb),
  };
  // só conecta depois que o renderer.js registrou os ouvintes: o servidor reenvia na hora
  // a última varredura, e eventos que chegassem antes disso seriam perdidos
  document.addEventListener('DOMContentLoaded', connect);
})();
