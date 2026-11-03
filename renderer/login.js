'use strict';

const form = document.getElementById('loginForm');
const err = document.getElementById('loginError');
const btn = document.getElementById('loginBtn');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  err.hidden = true;
  btn.disabled = true;
  try {
    const r = await fetch('/api/login', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Netscan': '1' },
      body: JSON.stringify({ password: document.getElementById('password').value }),
    });
    if (r.ok) { location.href = '/'; return; }
    err.textContent = (await r.json()).error || 'Não foi possível entrar.';
  } catch (_) {
    err.textContent = 'Servidor indisponível.';
  }
  err.hidden = false;
  btn.disabled = false;
  document.getElementById('password').select();
});
