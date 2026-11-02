'use strict';

const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { spawn, execFile } = require('child_process');
const path = require('path');
const readline = require('readline');

let win = null;
let currentProc = null;

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
  return args;
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

function startProcess(opts, useSudo) {
  const args = buildArgs(opts);
  let cmd, spawnArgs;
  if (useSudo) {
    cmd = 'sudo';
    spawnArgs = ['-n', 'python3', ...args]; // credencial já cacheada quando necessário
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
  return startProcess(opts, true);
});

ipcMain.handle('scan:stop', () => ({ ok: killScan() }));

ipcMain.handle('open:path', (_evt, p) => {
  if (p) shell.openPath(p);
  return { ok: true };
});
