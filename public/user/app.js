'use strict';

const state = {
  authenticated: false,
  authMode: 'totp',
  config: null,
  nodes: [],
  currentSession: null,
  deviceId: localStorage.getItem('redproxy_device_id') || '',
  downloading: false,
};

let pollTimer = null;
let refreshInFlight = false;

const $ = id => document.getElementById(id);
const setText = (id, value) => { const el = $(id); if (el) el.textContent = value; };
const toggle = (id, hidden) => { const el = $(id); if (el) el.classList.toggle('hidden', hidden); };

function fmtRemaining(seconds) {
  if (!seconds || seconds <= 0) return '0s';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h ? `${h}h` : '', m ? `${m}m` : '', `${s}s`].filter(Boolean).join(' ');
}

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  let body = options.body;
  if (body && typeof body !== 'string' && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  const response = await fetch(path, { ...options, headers, body, credentials: 'same-origin' });
  const text = await response.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch (_e) { data = { raw: text }; } }
  if (!response.ok) {
    const error = new Error((data && (data.message || data.error)) || `HTTP ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

function setAuthenticated(value) {
  state.authenticated = value;
  toggle('login-view', value);
  toggle('main-view', !value);
  toggle('logout-button', !value);
}

async function loadAuthMode() {
  try {
    const data = await api('/api/auth/mode');
    state.authMode = data.authMode;
    toggle('username-field', !data.passwordRequired);
    toggle('password-field', !data.passwordRequired);
    toggle('totp-field', !data.totpRequired);
    const hint = data.totpRequired && data.passwordRequired
      ? '请输入用户名、密码和动态验证码。'
      : data.passwordRequired
        ? '请输入用户名和密码。'
        : '请输入动态验证码。';
    setText('login-hint', hint);
  } catch (err) {
    console.error('auth mode', err);
  }
}

async function login(event) {
  event.preventDefault();
  setText('login-error', '');
  toggle('login-error', true);
  try {
    await api('/api/auth/totp', {
      method: 'POST',
      body: {
        username: $('username-field').classList.contains('hidden') ? undefined : $('username').value.trim(),
        password: $('password-field').classList.contains('hidden') ? undefined : $('password').value,
        token: $('totp-field').classList.contains('hidden') ? undefined : $('totp-token').value.trim(),
      },
    });
    setAuthenticated(true);
    await refreshAll();
    startPolling();
  } catch (err) {
    const details = err.data && err.data.details;
    let suffix = '';
    if (details && typeof details.attemptsRemaining === 'number') suffix = `（剩余尝试：${details.attemptsRemaining}）`;
    if (details && details.banned) suffix = `（IP 已临时封禁，请 ${details.retryAfterSeconds}s 后再试）`;
    const el = $('login-error');
    el.textContent = `${err.message}${suffix}`;
    el.classList.remove('hidden');
  }
}

async function logout() {
  try { await api('/api/auth/logout', { method: 'POST', body: {} }); } catch (err) { console.error(err); }
  setAuthenticated(false);
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

async function checkAuth() {
  await loadAuthMode();
  try {
    await api('/api/me');
    setAuthenticated(true);
    await refreshAll();
    startPolling();
  } catch (err) {
    if (err.status !== 401) console.error(err);
    setAuthenticated(false);
  }
}

async function refreshAll() {
  await Promise.all([loadConfig(), loadNodes(), loadCurrentSession()]);
}

async function loadConfig() {
  state.config = await api('/api/config');
  const select = $('ttl-select');
  select.innerHTML = '';
  (state.config.ttlOptions || [3600]).forEach(seconds => {
    const option = document.createElement('option');
    option.value = String(seconds);
    option.textContent = seconds % 3600 === 0 ? `${seconds / 3600} 小时` : `${Math.round(seconds / 60)} 分钟`;
    select.appendChild(option);
  });
  select.value = String(state.config.sessionTtlSeconds || 3600);
}

async function loadNodes() {
  const data = await api('/api/nodes');
  state.nodes = data.nodes || [];
  const select = $('node-select');
  select.innerHTML = '';
  state.nodes.forEach(node => {
    const option = document.createElement('option');
    option.value = node.id;
    option.textContent = `${node.name} · ${node.scheme}://${node.host}:${node.port}`;
    select.appendChild(option);
  });
  if (state.nodes.length === 0) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = '暂无可用节点';
    select.appendChild(option);
  }
}

function ensureDeviceId() {
  if (!state.deviceId) {
    state.deviceId = (crypto.randomUUID && crypto.randomUUID()) || `dev-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    localStorage.setItem('redproxy_device_id', state.deviceId);
  }
  return state.deviceId;
}

async function loadCurrentSession() {
  try {
    const data = await api('/api/session');
    state.currentSession = data.session || null;
    renderSession();
  } catch (err) { if (err.status !== 401) console.error(err); }
}

function renderSession() {
  const session = state.currentSession;
  const close = $('close-session');
  const active = session && (session.state === 'active' || session.state === 'pending');
  if (!active) {
    setText('session-status', '无会话');
    setText('session-message', session ? `上次会话：${session.state}` : '选择节点和有效期后生成临时 CRX。');
    close.disabled = true;
    return;
  }
  setText('session-status', session.state === 'pending' ? '待安装' : '会话活跃');
  setText('session-message',
    `节点 ${session.nodeName} · 剩余 ${fmtRemaining(session.remainingSeconds)} · ${session.enrolled ? '扩展已绑定' : '等待扩展首次心跳'}`);
  close.disabled = false;
}

async function createSessionIfNeeded(force = false) {
  if (!force && state.currentSession && (state.currentSession.state === 'active' || state.currentSession.state === 'pending')) {
    return state.currentSession;
  }
  const nodeId = $('node-select').value;
  if (!nodeId) throw new Error('暂无可用节点');
  const ttlSeconds = Number($('ttl-select').value || 3600);
  const data = await api('/api/session', { method: 'POST', body: { deviceId: ensureDeviceId(), nodeId, ttlSeconds } });
  state.currentSession = data.session;
  renderSession();
  return state.currentSession;
}

async function fetchExtension(kind) {
  const path = `/api/session/extension.${kind}`;
  let response = await fetch(path, { credentials: 'same-origin' });
  if (response.status === 404) {
    // A previous page navigation (pagehide sendBeacon) may have revoked the
    // session right before the download. Recreate it once and retry.
    const text = await response.text();
    if (text.includes('session_not_found')) {
      await createSessionIfNeeded(true);
      response = await fetch(path, { credentials: 'same-origin' });
    } else {
      let message = `HTTP ${response.status}`;
      try { const data = JSON.parse(text); message = data.message || data.error || message; } catch (_e) { /* ignore */ }
      throw new Error(message);
    }
  }
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try { const data = await response.json(); message = data.message || data.error || message; } catch (_e) { /* ignore */ }
    throw new Error(message);
  }
  return response.blob();
}

async function generate(kind) {
  state.downloading = true;
  try {
    await createSessionIfNeeded();
    const blob = await fetchExtension(kind);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `redproxy-${kind}.${kind}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    setText('session-message', `已开始下载 ${kind.toUpperCase()}。`);
  } catch (err) {
    setText('session-message', err.message);
  } finally {
    state.downloading = false;
  }
}

async function revokeSession() {
  try {
    await api('/api/session/revoke', { method: 'POST', body: {} });
    state.currentSession = null;
    renderSession();
  } catch (err) { setText('session-message', err.message); }
}

function tick() {
  const session = state.currentSession;
  if (!session || (session.state !== 'active' && session.state !== 'pending')) return;
  const remaining = Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000));
  session.remainingSeconds = remaining;
  setText('session-message',
    `节点 ${session.nodeName} · 剩余 ${fmtRemaining(remaining)} · ${session.enrolled ? '扩展已绑定' : '等待扩展首次心跳'}`);
  const idle = Math.floor((Date.now() - session.lastHeartbeatAt) / 1000);
  if (idle > 30) void refreshSession();
  if (remaining <= 0) { state.currentSession = null; renderSession(); }
}

async function refreshSession() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try { await loadCurrentSession(); } finally { refreshInFlight = false; }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(tick, 1000);
}

function pagehideRevoke() {
  // Never revoke while a download is in flight: the download request itself
  // must not be cancelled by the pagehide beacon.
  if (state.downloading) return;
  const session = state.currentSession;
  if (!session || (session.state !== 'active' && session.state !== 'pending')) return;
  try {
    navigator.sendBeacon('/api/session/revoke', new Blob([JSON.stringify({ reason: 'pagehide' })], { type: 'application/json' }));
  } catch (err) { console.error('sendBeacon failed', err); }
}

document.addEventListener('DOMContentLoaded', () => {
  $('login-form').addEventListener('submit', login);
  $('logout-button').addEventListener('click', logout);
  $('generate-crx').addEventListener('click', () => generate('crx'));
  $('download-zip').addEventListener('click', () => generate('zip'));
  $('close-session').addEventListener('click', revokeSession);
  window.addEventListener('pagehide', pagehideRevoke);
  window.addEventListener('beforeunload', pagehideRevoke);
  void checkAuth();
});
