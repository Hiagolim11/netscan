'use strict';

const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { spawn, execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const net = require('net');
const readline = require('readline');

let win = null;
let currentProc = null;
// senha do sudo guardada só em memória e só enquanto o monitoramento estiver ativo
let monitorPassword = null;
const REPORT_DIR_RE = /^resultados_[\w-]+$/;

function createWindow() {
  win = new BrowserWindow({
    width: 1200,
    height: 820,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0e0f12',
    title: 'netscan',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  killScan();
  if (process.platform !== 'darwin') app.quit();
});

// ---------- helpers ----------

function scriptPath() {
  return app.isPackaged
    ? path.join(process.resourcesPath, 'netscan.py')
    : path.join(__dirname, 'netscan.py');
}

function workDir() {
  return app.isPackaged ? app.getPath('home') : __dirname;
}

function buildArgs(opts) {
  const args = [scriptPath(), '--json-stream'];
  if (opts && opts.target) args.push('-t', String(opts.target));
  if (opts && opts.fast) args.push('--fast');
  if (opts && opts.deep) args.push('--deep');
  // os valores são validados pelo netscan.py; aqui só repassamos como argumentos (sem shell)
  if (opts && opts.ports) args.push('-p', String(opts.ports));
  if (opts && opts.exclude) args.push('-x', String(opts.exclude));
  if (opts && opts.udp) args.push('--udp');
  if (opts && opts.noPing) args.push('--no-ping');
  if (opts && opts.ipv6) args.push('--ipv6');
  if (opts && opts.workers) args.push('-w', String(parseInt(opts.workers, 10) || 1));
  // re-scan de um host vai para outra pasta: não vira a "última varredura" da comparação
  if (opts && opts.single) {
    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '_').slice(0, 15);
    args.push('-o', path.join(workDir(), `rescan_${stamp}`));
  }
  if (opts && opts.compare) {
    const prev = opts.compare === 'latest' ? latestReport() : reportFile(opts.compare);
    if (prev) args.push('--compare', prev);
  }
  return args;
}

// caminho do relatorio.json de uma pasta do histórico (só nomes resultados_*, sem ../)
function reportFile(name) {
  if (!REPORT_DIR_RE.test(String(name))) return null;
  const f = path.join(workDir(), name, 'relatorio.json');
  return fs.existsSync(f) ? f : null;
}

// relatorio.json da varredura mais recente em workDir (nomes resultados_<data> ordenam por data)
function latestReport() {
  try {
    const dirs = fs.readdirSync(workDir())
      .filter((d) => d.startsWith('resultados_'))
      .sort()
      .reverse();
    for (const d of dirs) {
      const f = path.join(workDir(), d, 'relatorio.json');
      if (fs.existsSync(f)) return f;
    }
  } catch (_) {}
  return null;
}

// true = sudo sem senha disponível; false = exige senha; 'nosudo' = sudo ausente
function checkSudo() {
  return new Promise((resolve) => {
    execFile('sudo', ['-n', 'true'], (err) => {
      if (!err) return resolve(true);
      // distingue "sudo ausente" de "precisa de senha"
      if (err && err.code === 'ENOENT') return resolve('nosudo');
      resolve(false);
    });
  });
}

// valida a senha e cacheia a credencial do sudo (sudo -v). Não loga a senha.
function validateSudoPassword(password) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn('sudo', ['-S', '-k', '-p', '', '-v']);
    } catch (e) {
      return resolve({ ok: false, error: String(e) });
    }
    let err = '';
    child.stderr.on('data', (d) => { err += d.toString(); });
    child.on('error', (e) => resolve({ ok: false, error: String(e.message || e) }));
    child.on('close', (code) => resolve({ ok: code === 0, error: code === 0 ? '' : 'senha incorreta' }));
    try {
      child.stdin.write(password + '\n');
      child.stdin.end();
    } catch (_) {}
  });
}

// sudoMode: null = sem sudo; true = sudo sem senha (-n); string = senha (passada via -S)
function startProcess(opts, sudoMode) {
  const args = buildArgs(opts);
  let cmd, spawnArgs;
  const withPassword = typeof sudoMode === 'string';
  if (sudoMode === true) {
    cmd = 'sudo';
    spawnArgs = ['-n', 'python3', ...args];
  } else if (withPassword) {
    cmd = 'sudo';
    // -S lê a senha do stdin; a senha é consumida só pela autenticação do sudo
    spawnArgs = ['-S', '-p', '', 'python3', ...args];
  } else {
    cmd = 'python3';
    spawnArgs = args;
  }

  try {
    // próprio grupo de processos para encerrar nmap junto (robustez ao parar)
    currentProc = spawn(cmd, spawnArgs, { cwd: workDir(), detached: true });
  } catch (e) {
    currentProc = null;
    return { ok: false, error: String(e) };
  }

  if (withPassword) {
    try {
      currentProc.stdin.write(sudoMode + '\n');
      currentProc.stdin.end();
    } catch (_) {}
  }

  const rl = readline.createInterface({ input: currentProc.stdout });
  rl.on('line', (line) => {
    line = line.trim();
    if (!line) return;
    try {
      const evt = JSON.parse(line);
      if (win && !win.isDestroyed()) win.webContents.send('scan:event', evt);
    } catch (_) { /* linha não-JSON: ignora */ }
  });

  let stderrBuf = '';
  currentProc.stderr.on('data', (d) => {
    stderrBuf += d.toString();
    const parts = stderrBuf.split('\n');
    stderrBuf = parts.pop();
    for (const l of parts) {
      if (l.trim() && win && !win.isDestroyed()) win.webContents.send('scan:log', l.trim());
    }
  });

  currentProc.on('error', (err) => {
    if (win && !win.isDestroyed()) win.webContents.send('scan:error', String(err.message || err));
    currentProc = null;
  });

  currentProc.on('close', (code) => {
    if (win && !win.isDestroyed()) win.webContents.send('scan:close', { code });
    currentProc = null;
  });

  return { ok: true };
}

function killScan() {
  if (!currentProc) return false;
  const pid = currentProc.pid;
  try {
    // mata o grupo inteiro (python + nmap filho)
    process.kill(-pid, 'SIGTERM');
  } catch (_) {
    try { currentProc.kill('SIGTERM'); } catch (__) {}
  }
  return true;
}

// ---------- IPC ----------

// Decide se precisa de senha. Se sim, devolve needPassword para o renderer abrir o modal.
ipcMain.handle('scan:start', async (_evt, opts) => {
  if (currentProc) return { ok: false, error: 'Já existe uma varredura em andamento.' };

  if (opts && opts.useSudo) {
    const s = await checkSudo();
    if (s === 'nosudo') {
      return { ok: false, error: 'sudo não encontrado. Desmarque a opção sudo ou instale o sudo.' };
    }
    if (s === false) {
      if (opts.repeat && monitorPassword) return startProcess(opts, monitorPassword);
      return { ok: false, needPassword: true }; // renderer abre o diálogo de senha
    }
    // s === true: sudo sem senha
    return startProcess(opts, true);
  }
  return startProcess(opts, false);
});

// Chamado após o usuário digitar a senha no modal.
ipcMain.handle('scan:start-sudo', async (_evt, opts, password) => {
  if (currentProc) return { ok: false, error: 'Já existe uma varredura em andamento.' };
  const v = await validateSudoPassword(password || '');
  if (!v.ok) return { ok: false, badPassword: true, error: v.error || 'senha incorreta' };
  if (opts && opts.repeat) monitorPassword = password;
  // passa a senha direto ao sudo do scan (-S), sem depender do cache de credenciais
  return startProcess(opts, password || '');
});

ipcMain.handle('scan:stop', () => ({ ok: killScan() }));

ipcMain.handle('monitor:stop', () => { monitorPassword = null; return { ok: true }; });

ipcMain.handle('history:list', () => {
  try {
    return fs.readdirSync(workDir())
      .filter((d) => REPORT_DIR_RE.test(d) && reportFile(d))
      .sort().reverse().slice(0, 30)
      .map((name) => {
        try {
          const r = JSON.parse(fs.readFileSync(reportFile(name), 'utf8'));
          return { name, timestamp: r.timestamp, target: r.target, hosts: (r.hosts || []).length, totals: r.totals || {} };
        } catch (_) { return null; }
      })
      .filter(Boolean);
  } catch (_) { return []; }
});

ipcMain.handle('history:load', (_evt, name) => {
  const f = reportFile(name);
  if (!f) return { ok: false, error: 'Relatório não encontrado.' };
  try {
    return { ok: true, report: JSON.parse(fs.readFileSync(f, 'utf8')), outdir: path.dirname(f) };
  } catch (e) { return { ok: false, error: String(e.message || e) }; }
});

ipcMain.handle('open:path', (_evt, p) => {
  if (p) shell.openPath(p);
  return { ok: true };
});

// abre a página do exploit no Exploit-DB (só aceita o ID numérico)
ipcMain.handle('open:edb', (_evt, id) => {
  if (!/^\d{1,7}$/.test(String(id))) return { ok: false };
  shell.openExternal(`https://www.exploit-db.com/exploits/${id}`);
  return { ok: true };
});

// abre http(s)://ip:porta no navegador; a URL é montada aqui para não aceitar URLs arbitrárias
ipcMain.handle('open:web', (_evt, ip, port, tls) => {
  const n = parseInt(port, 10);
  if (!net.isIP(String(ip)) || !(n > 0 && n < 65536)) return { ok: false };
  const host = net.isIPv6(ip) ? `[${ip}]` : ip;
  shell.openExternal(`${tls ? 'https' : 'http'}://${host}:${n}/`);
  return { ok: true };
});
