'use strict';

const state = {
  authenticated: false,
  config: null,
  nodes: [],
  currentSession: null,
  deviceId: localStorage.getItem('redproxy_device_id') || '',
};

let pollTimer = null;
let refreshInFlight = false;

function $(id) { return document.getElementById(id); }
function setText(id, value) { const node = $(id); if (node) node.textContent = value; }
function setHidden(id, hidden) { const node = $(id); if (node) node.classList.toggle('hidden', hidden); }

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

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
    error.status = response.status; error.data = data;
    throw error;
  }
  return data;
}

function setAuthenticated(value) {
  state.authenticated = value;
  setHidden('login-view', value);
  setHidden('main-view', !value);
  setHidden('top-actions', !value);
}

async function login(event) {
  event.preventDefault();
  setText('login-error', '');
  const token = $('totp-token').value.trim();
  try {
    await api('/api/auth/totp', { method: 'POST', body: { token } });
    setAuthenticated(true);
    $('totp-token').value = '';
    await refreshAll();
    startPolling();
  } catch (err) {
    const details = err.data && err.data.details;
    let suffix = '';
    if (details && typeof details.attemptsRemaining === 'number') suffix = `（剩余尝试：${details.attemptsRemaining}）`;
    if (details && details.banned) suffix = `（该 IP 已被临时封禁，请 ${details.retryAfterSeconds}s 后再试）`;
    setText('login-error', `${err.message}${suffix}`);
  }
}

async function logout() {
  try { await api('/api/auth/logout', { method: 'POST', body: {} }); } catch (err) { console.error(err); }
  setAuthenticated(false);
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

async function checkAuth() {
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
  renderTtlOptions();
}

function renderTtlOptions() {
  const select = $('ttl-select');
  if (!select || !state.config) return;
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
  renderNodes();
}

function renderNodes() {
  const select = $('node-select');
  if (!select) return;
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
    option.textContent = '当前没有可用节点，请联系管理员';
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
    renderCurrentSession();
  } catch (err) { if (err.status !== 401) console.error(err); }
}

function renderCurrentSession() {
  const session = state.currentSession;
  const closeButton = $('close-session');
  if (!session || (session.state !== 'active' && session.state !== 'pending')) {
    setText('session-status', '无会话');
    setText('session-message', session ? `上次会话状态：${session.state}` : '选择节点和有效期后生成临时 CRX。');
    if (closeButton) closeButton.disabled = true;
    return;
  }
  setText('session-status', session.state === 'pending' ? '待安装' : '会话活跃');
  setText('session-message',
    `设备 ${session.deviceId} 使用节点 ${session.nodeName}；剩余 ${fmtRemaining(session.remainingSeconds)}。${session.enrolled ? '扩展已绑定。' : '等待扩展首次心跳（CRX token 一次性）。'}`);
  if (closeButton) closeButton.disabled = false;
}

async function createSessionIfNeeded() {
  if (state.currentSession && (state.currentSession.state === 'active' || state.currentSession.state === 'pending')) {
    return state.currentSession;
  }
  const nodeId = $('node-select').value;
  if (!nodeId) throw new Error('当前没有可用节点，请联系管理员');
  const ttlSeconds = Number($('ttl-select').value || 3600);
  const data = await api('/api/session', { method: 'POST', body: { deviceId: ensureDeviceId(), nodeId, ttlSeconds } });
  state.currentSession = data.session;
  renderCurrentSession();
  return state.currentSession;
}

async function generateCrx() {
  try { await createSessionIfNeeded(); window.location.href = '/api/session/extension.crx'; }
  catch (err) { setText('session-message', err.message); }
}

async function downloadZip() {
  try { await createSessionIfNeeded(); window.location.href = '/api/session/extension.zip'; }
  catch (err) { setText('session-message', err.message); }
}

async function revokeSession() {
  try {
    await api('/api/session/revoke', { method: 'POST', body: {} });
    state.currentSession = null;
    renderCurrentSession();
  } catch (err) { setText('session-message', err.message); }
}

function tick() {
  const session = state.currentSession;
  if (!session || (session.state !== 'active' && session.state !== 'pending')) return;
  const remaining = Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000));
  session.remainingSeconds = remaining;
  setText('session-message',
    `设备 ${session.deviceId} 使用节点 ${session.nodeName}；剩余 ${fmtRemaining(remaining)}。${session.enrolled ? '扩展已绑定。' : '等待扩展首次心跳（CRX token 一次性）。'}`);
  const idle = Math.floor((Date.now() - session.lastHeartbeatAt) / 1000);
  if (idle > 30) void refreshSession();
  if (remaining <= 0) { state.currentSession = null; renderCurrentSession(); }
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
  const session = state.currentSession;
  if (!session || (session.state !== 'active' && session.state !== 'pending')) return;
  try {
    const payload = new Blob([JSON.stringify({ reason: 'pagehide' })], { type: 'application/json' });
    navigator.sendBeacon('/api/session/revoke', payload);
  } catch (err) { console.error('sendBeacon failed', err); }
}

document.addEventListener('DOMContentLoaded', () => {
  $('login-form').addEventListener('submit', login);
  $('logout-button').addEventListener('click', logout);
  $('generate-crx').addEventListener('click', generateCrx);
  $('download-zip').addEventListener('click', downloadZip);
  $('close-session').addEventListener('click', revokeSession);
  window.addEventListener('pagehide', pagehideRevoke);
  window.addEventListener('beforeunload', pagehideRevoke);
  void checkAuth();
  void escapeHtml;
});
