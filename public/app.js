'use strict';

const state = {
  authenticated: false,
  config: null,
  nodes: [],
  sessions: [],
  currentSession: null,
  deviceId: localStorage.getItem('redproxy_device_id') || '',
};

const els = {};
let timer = null;
let refreshInFlight = false;

function $(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const node = $(id);
  if (node) node.textContent = value;
}

function setHidden(id, hidden) {
  const node = $(id);
  if (node) node.classList.toggle('hidden', hidden);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  let body = options.body;
  if (body && typeof body !== 'string') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  const response = await fetch(path, {
    ...options,
    headers,
    body,
    credentials: 'same-origin',
  });
  let data = null;
  const text = await response.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (_err) {
      data = { raw: text };
    }
  }
  if (!response.ok) {
    const error = new Error((data && (data.message || data.error)) || `HTTP ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

function fmtTime(timestamp) {
  if (!timestamp) return '-';
  try {
    return new Date(timestamp).toLocaleString();
  } catch (_err) {
    return '-';
  }
}

function fmtRemaining(seconds) {
  if (seconds <= 0) return '0s';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h ? `${h}h` : '', m ? `${m}m` : '', `${s}s`].filter(Boolean).join(' ');
}

async function checkAuth() {
  try {
    await api('/api/me');
    state.authenticated = true;
  } catch (err) {
    if (err.status !== 401) console.error(err);
    state.authenticated = false;
  }
  renderAuth();
  if (state.authenticated) {
    await Promise.all([loadConfig(), loadNodes(), loadSessions(), loadCurrentSession()]);
    startTimer();
  }
}

function renderAuth() {
  setHidden('login-view', state.authenticated);
  setHidden('main-view', !state.authenticated);
  setHidden('top-actions', !state.authenticated);
  setText('auth-status', state.authenticated ? '已登录' : '未登录');
}

async function login(event) {
  event.preventDefault();
  setText('login-error', '');
  const token = $('totp-token').value.trim();
  try {
    await api('/api/auth/totp', { method: 'POST', body: { token } });
    state.authenticated = true;
    $('totp-token').value = '';
    renderAuth();
    await Promise.all([loadConfig(), loadNodes(), loadSessions(), loadCurrentSession()]);
    startTimer();
  } catch (err) {
    const remaining = err.data && err.data.details && typeof err.data.details.attemptsRemaining === 'number'
      ? `（剩余尝试次数：${err.data.details.attemptsRemaining}）`
      : '';
    setText('login-error', `${err.message}${remaining}`);
  }
}

async function logout() {
  try {
    await api('/api/auth/logout', { method: 'POST', body: {} });
  } catch (err) {
    console.error(err);
  }
  state.authenticated = false;
  state.currentSession = null;
  renderAuth();
  if (timer) clearInterval(timer);
  timer = null;
}

async function loadConfig() {
  try {
    state.config = await api('/api/config');
    renderTtlOptions();
  } catch (err) {
    console.error('loadConfig', err);
  }
}

function renderTtlOptions() {
  const select = $('ttl-select');
  if (!select || !state.config) return;
  select.innerHTML = '';
  (state.config.ttlOptions || [3600]).forEach(seconds => {
    const option = document.createElement('option');
    option.value = String(seconds);
    const minutes = Math.round(seconds / 60);
    option.textContent = minutes >= 60 && minutes % 60 === 0 ? `${minutes / 60} 小时` : `${minutes} 分钟`;
    select.appendChild(option);
  });
  select.value = String(state.config.sessionTtlSeconds || 3600);
}

async function loadNodes() {
  try {
    const data = await api('/api/admin/nodes');
    state.nodes = data.nodes || [];
    renderNodes();
  } catch (err) {
    console.error('loadNodes', err);
  }
}

function renderNodes() {
  const body = $('nodes-body');
  const select = $('node-select');
  if (!body || !select) return;
  body.innerHTML = '';
  select.innerHTML = '';

  const enabledNodes = state.nodes.filter(node => node.enabled);
  enabledNodes.forEach(node => {
    const option = document.createElement('option');
    option.value = node.id;
    option.textContent = `${node.name} (${node.scheme}://${node.host}:${node.port})`;
    select.appendChild(option);
  });
  if (enabledNodes.length === 0) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = '没有可用节点';
    select.appendChild(option);
  }

  state.nodes.forEach(node => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(node.name)}</td>
      <td>${escapeHtml(node.scheme)}</td>
      <td class="mono">${escapeHtml(node.host)}:${escapeHtml(node.port)}</td>
      <td>${node.enabled ? '<span style="color:var(--ok)">启用</span>' : '<span class="muted">停用</span>'}${node.hasAuth ? ' · 认证' : ''}</td>
      <td>
        <button class="secondary small" data-action="toggle" data-id="${escapeHtml(node.id)}">${node.enabled ? '停用' : '启用'}</button>
        <button class="danger small" data-action="delete" data-id="${escapeHtml(node.id)}">删除</button>
      </td>`;
    body.appendChild(tr);
  });
}

async function addNode(event) {
  event.preventDefault();
  setText('node-error', '');
  const form = event.currentTarget;
  const formData = new FormData(form);
  const payload = {
    name: String(formData.get('name') || '').trim(),
    scheme: String(formData.get('scheme') || 'http'),
    host: String(formData.get('host') || '').trim(),
    port: Number(formData.get('port')),
    username: String(formData.get('username') || '').trim() || null,
    password: String(formData.get('password') || '') || null,
    enabled: true,
  };
  try {
    await api('/api/admin/nodes', { method: 'POST', body: payload });
    form.reset();
    await loadNodes();
  } catch (err) {
    setText('node-error', err.message);
  }
}

async function handleNodeAction(event) {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const id = button.getAttribute('data-id');
  const action = button.getAttribute('data-action');
  if (!id || !action) return;
  try {
    if (action === 'delete') {
      if (!window.confirm('确定删除这个节点吗？')) return;
      await api(`/api/admin/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' });
    } else if (action === 'toggle') {
      const node = state.nodes.find(item => item.id === id);
      if (!node) return;
      await api(`/api/admin/nodes/${encodeURIComponent(id)}`, { method: 'PATCH', body: { enabled: !node.enabled } });
    }
    await loadNodes();
  } catch (err) {
    setText('node-error', err.message);
  }
}

async function loadSessions() {
  try {
    const data = await api('/api/admin/sessions');
    state.sessions = data.sessions || [];
    state.maxConcurrentDevices = data.maxConcurrentDevices;
    renderSessions();
  } catch (err) {
    console.error('loadSessions', err);
  }
}

function renderSessions() {
  const body = $('sessions-body');
  if (!body) return;
  body.innerHTML = '';
  setText('max-devices', `最大并发设备：${state.maxConcurrentDevices ?? '-'}`);

  const sessions = state.sessions.length ? state.sessions : [];
  if (sessions.length === 0) {
    body.innerHTML = '<tr><td colspan="6" class="muted">暂无会话</td></tr>';
    return;
  }

  sessions.forEach(session => {
    const tr = document.createElement('tr');
    const stateText = session.state === 'active' ? '活跃' : session.state === 'revoked' ? '已撤销' : '已过期/空闲';
    tr.innerHTML = `
      <td class="mono">${escapeHtml(session.deviceId)}</td>
      <td>${escapeHtml(session.nodeName)}</td>
      <td>${stateText}</td>
      <td>${session.state === 'active' ? fmtRemaining(session.remainingSeconds) : '-'}</td>
      <td>${fmtTime(session.expiresAt)}</td>
      <td>${session.state === 'active' ? `<button class="danger small" data-action="revoke" data-id="${escapeHtml(session.id)}">撤销</button>` : '-'}</td>`;
    body.appendChild(tr);
  });
}

async function handleSessionAction(event) {
  const button = event.target.closest('button[data-action="revoke"]');
  if (!button) return;
  const id = button.getAttribute('data-id');
  if (!id) return;
  try {
    await api(`/api/admin/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
    await Promise.all([loadSessions(), loadCurrentSession()]);
  } catch (err) {
    setText('admin-error', err.message);
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
  } catch (err) {
    if (err.status === 401) {
      state.authenticated = false;
      renderAuth();
    } else {
      console.error('loadCurrentSession', err);
    }
  }
}

function renderCurrentSession() {
  const session = state.currentSession;
  if (!session || session.state !== 'active') {
    setText('session-status', '无活跃会话');
    setText('session-message', session ? `上次会话状态：${session.state}` : '选择节点后点击“生成临时 CRX”。');
    setText('close-session', '关闭当前会话');
    const closeButton = $('close-session');
    if (closeButton) closeButton.disabled = true;
    return;
  }
  setText('session-status', '会话活跃');
  setText('session-message', `设备 ${session.deviceId} 正在使用节点 ${session.nodeName}；剩余 ${fmtRemaining(session.remainingSeconds)}。`);
  const closeButton = $('close-session');
  if (closeButton) closeButton.disabled = false;
}

async function createSessionIfNeeded() {
  if (state.currentSession && state.currentSession.state === 'active') return state.currentSession;
  const nodeId = $('node-select') ? $('node-select').value : '';
  if (!nodeId) throw new Error('请先添加并启用一个代理节点');
  const ttlSeconds = Number($('ttl-select').value || 3600);
  const data = await api('/api/session', {
    method: 'POST',
    body: { deviceId: ensureDeviceId(), nodeId, ttlSeconds },
  });
  state.currentSession = data.session;
  renderCurrentSession();
  await loadSessions();
  return state.currentSession;
}

async function generateCrx() {
  try {
    await createSessionIfNeeded();
    window.location.href = '/api/session/extension.crx';
  } catch (err) {
    setText('session-message', err.message);
  }
}

async function downloadZip() {
  try {
    await createSessionIfNeeded();
    window.location.href = '/api/session/extension.zip';
  } catch (err) {
    setText('session-message', err.message);
  }
}

async function revokeSession() {
  try {
    await api('/api/session/revoke', { method: 'POST', body: {} });
    state.currentSession = null;
    renderCurrentSession();
    await loadSessions();
  } catch (err) {
    setText('session-message', err.message);
  }
}

async function showTotpUri() {
  try {
    const data = await api('/api/admin/totp');
    setText('totp-uri', data.otpauthUri || '');
  } catch (err) {
    setText('admin-error', err.message);
  }
}

function tick() {
  if (!state.currentSession || state.currentSession.state !== 'active') {
    if (state.currentSession) renderCurrentSession();
    return;
  }
  const elapsed = Math.floor((Date.now() - state.currentSession.lastHeartbeatAt) / 1000);
  const remaining = Math.max(0, Math.ceil((state.currentSession.expiresAt - Date.now()) / 1000));
  state.currentSession.remainingSeconds = remaining;
  setText('session-message', `设备 ${state.currentSession.deviceId} 正在使用节点 ${state.currentSession.nodeName}；剩余 ${fmtRemaining(remaining)}。`);
  if (elapsed > 15 * 3 && remaining > 0) {
    // The extension should heartbeat every 15s. If the page is still open and
    // the session appears stale, refresh from the server, but keep local TTL as
    // the final fallback.
    void refreshSession();
  }
  if (remaining <= 0) {
    state.currentSession = null;
    renderCurrentSession();
  }
}

async function refreshSession() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    await loadCurrentSession();
  } finally {
    refreshInFlight = false;
  }
}

function startTimer() {
  if (timer) clearInterval(timer);
  timer = setInterval(() => {
    tick();
  }, 1000);
  setInterval(() => {
    if (state.authenticated) {
      void loadSessions();
    }
  }, 10000);
}

function pagehideRevoke() {
  if (!state.currentSession || state.currentSession.state !== 'active') return;
  try {
    const payload = new Blob([JSON.stringify({ reason: 'pagehide' })], { type: 'application/json' });
    navigator.sendBeacon('/api/session/revoke', payload);
  } catch (err) {
    console.error('sendBeacon revoke failed', err);
  }
}

function initEvents() {
  $('login-form').addEventListener('submit', login);
  $('logout-button').addEventListener('click', logout);
  $('node-form').addEventListener('submit', addNode);
  $('nodes-body').addEventListener('click', handleNodeAction);
  $('sessions-body').addEventListener('click', handleSessionAction);
  $('generate-crx').addEventListener('click', generateCrx);
  $('download-zip').addEventListener('click', downloadZip);
  $('close-session').addEventListener('click', revokeSession);
  $('show-totp-uri').addEventListener('click', showTotpUri);
  window.addEventListener('pagehide', pagehideRevoke);
  window.addEventListener('beforeunload', pagehideRevoke);
}

document.addEventListener('DOMContentLoaded', () => {
  initEvents();
  void checkAuth();
});
