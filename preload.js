'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('netscan', {
  start: (opts) => ipcRenderer.invoke('scan:start', opts),
  startSudo: (opts, password) => ipcRenderer.invoke('scan:start-sudo', opts, password),
  stop: () => ipcRenderer.invoke('scan:stop'),
  openPath: (p) => ipcRenderer.invoke('open:path', p),
  onEvent: (cb) => ipcRenderer.on('scan:event', (_e, data) => cb(data)),
  onLog: (cb) => ipcRenderer.on('scan:log', (_e, line) => cb(line)),
  onError: (cb) => ipcRenderer.on('scan:error', (_e, msg) => cb(msg)),
  onClose: (cb) => ipcRenderer.on('scan:close', (_e, info) => cb(info)),
});
