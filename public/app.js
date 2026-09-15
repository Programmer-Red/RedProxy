'use strict';

const state = {
  authenticated: false,
  config: null,
  nodes: [],
  sessions: [],
  logs: [],
  bans: [],
  authSettings: null,
  authMode: 'totp',
  currentSession: null,
  activeTab: 'use',
  deviceId: localStorage.getItem('redproxy_device_id') || '',
};

let pollTimer = null;
let refreshInFlight = false;

function $(id) { return document.getElementById(id); }
function setText(id, value) { const node = $(id); if (node) node.textContent = value; }
function setHidden(id, hidden) { const node = $(id); if (node) node.classList.toggle('hidden', hidden); }
function show(id, visible) { setHidden(id, !visible); }

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function fmtTime(ts) {
  if (!ts) return '-';
  try { return new Date(ts).toLocaleString(); } catch (_e) { return '-'; }
}

function fmtRemaining(seconds) {
  if (!seconds || seconds <= 0) return '0s';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h ? `${h}h` : '', m ? `${m}m` : '', `${s}s`].filter(Boolean).join(' ');
}

function downloadBlob(filename, content, type) {
  const blob = new Blob([content], { type: type || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
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
    if (response.status === 401 && state.authenticated) { setAuthenticated(false); }
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
  const password = $('admin-password') ? $('admin-password').value : '';
  try {
    await api('/api/auth/totp', { method: 'POST', body: { token, password } });
    setAuthenticated(true);
    if ($('totp-token')) $('totp-token').value = '';
    if ($('admin-password')) $('admin-password').value = '';
    await refreshAll();
    startPolling();
  } catch (err) {
    const details = err.data && err.data.details;
    const suffix = details && typeof details.attemptsRemaining === 'number' ? `（剩余尝试：${details.attemptsRemaining}）` : '';
    setText('login-error', `${err.message}${suffix}`);
  }
}

async function logout() {
  try { await api('/api/auth/logout', { method: 'POST', body: {} }); } catch (err) { console.error(err); }
  setAuthenticated(false);
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

async function loadAuthMode() {
  try {
    const data = await api('/api/auth/mode');
    state.authMode = data.authMode;
    const pwdField = $('password-field');
    if (pwdField) pwdField.classList.toggle('hidden', data.authMode !== 'totp_password');
    setText('password-hint', data.authMode === 'totp_password' ? '和管理员密码' : '');
  } catch (err) { console.error('auth mode', err); }
}

async function checkAuth() {
  await loadAuthMode();
  try { await api('/api/me'); setAuthenticated(true); await refreshAll(); startPolling(); }
  catch (err) { if (err.status !== 401) console.error(err); setAuthenticated(false); }
}

async function refreshAll() {
  await Promise.all([loadConfig(), loadNodes(), loadSessions(), loadCurrentSession(), loadSecurity(), loadLogs()]);
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
  const data = await api('/api/admin/nodes');
  state.nodes = data.nodes || [];
  renderNodes();
}

function nodeProxyAddress(node) {
  if (node.kind === 'xray') return `${node.host}:${node.port}`;
  return `${node.host}:${node.port}`;
}

function nodeLocalAddress(node) {
  if (node.kind !== 'xray') return `${node.scheme}://${node.host}:${node.port}`;
  return `${node.localScheme || 'socks5'}://${node.localHost || '127.0.0.1'}:${node.localPort || 10808}`;
}

function renderNodes() {
  const body = $('nodes-body');
  const select = $('node-select');
  if (!body || !select) return;
  body.innerHTML = '';
  select.innerHTML = '';

  const enabled = state.nodes.filter(node => node.enabled);
  enabled.forEach(node => {
    const option = document.createElement('option');
    option.value = node.id;
    option.textContent = `${node.name} · ${nodeLocalAddress(node)}`;
    select.appendChild(option);
  });
  if (enabled.length === 0) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = '没有可用节点';
    select.appendChild(option);
  }

  state.nodes.forEach(node => {
    const tr = document.createElement('tr');
    const type = node.kind === 'xray' ? `Xray/${node.xray ? node.xray.protocol : '?'}` : node.scheme;
    const actions = [
      `<button class="secondary small" data-action="toggle" data-id="${escapeHtml(node.id)}">${node.enabled ? '停用' : '启用'}</button>`,
      node.kind === 'xray' ? `<button class="secondary small" data-action="xray" data-id="${escapeHtml(node.id)}">导出配置</button>` : '',
      `<button class="danger small" data-action="delete" data-id="${escapeHtml(node.id)}">删除</button>`,
    ].filter(Boolean).join(' ');
    tr.innerHTML = `
      <td>${escapeHtml(node.name)}</td>
      <td>${escapeHtml(type)}</td>
      <td class="mono">${escapeHtml(nodeProxyAddress(node))}</td>
      <td class="mono">${escapeHtml(nodeLocalAddress(node))}</td>
      <td>${node.enabled ? '<span class="ok">启用</span>' : '<span class="muted">停用</span>'}${node.hasAuth ? ' · 认证' : ''}</td>
      <td>${actions}</td>`;
    body.appendChild(tr);
  });
}

function buildNodePayload() {
  const kind = $('node-kind').value;
  const name = $('node-name').value.trim();
  const enabled = $('node-enabled').value === 'true';
  if (kind === 'proxy') {
    return {
      kind, name, enabled,
      scheme: $('proxy-scheme').value,
      host: $('proxy-host').value.trim(),
      port: Number($('proxy-port').value),
      username: $('proxy-username').value.trim() || null,
      password: $('proxy-password').value || null,
    };
  }
  const protocol = $('xray-protocol').value;
  const xray = {
    protocol,
    uuid: $('xray-uuid').value.trim() || null,
    password: $('xray-password').value || null,
    method: $('xray-method').value.trim() || null,
    alterId: Number($('xray-alterid').value || 0),
    flow: $('xray-flow').value.trim() || null,
    network: $('xray-network').value || 'tcp',
    security: $('xray-security').value || null,
    sni: $('xray-sni').value.trim() || null,
    host: $('xray-host-header').value.trim() || null,
    path: $('xray-path').value.trim() || null,
    serviceName: $('xray-path').value.trim() || null,
    fingerprint: $('xray-fingerprint').value.trim() || null,
    publicKey: $('xray-public-key').value.trim() || null,
    shortId: $('xray-short-id').value.trim() || null,
    spiderX: $('xray-spider-x').value.trim() || null,
    allowInsecure: false,
  };
  return {
    kind, name, enabled,
    scheme: 'socks5',
    host: $('xray-host').value.trim(),
    port: Number($('xray-port').value),
    username: null,
    password: null,
    xray,
    localScheme: $('local-scheme').value,
    localHost: $('local-host').value.trim() || '127.0.0.1',
    localPort: Number($('local-port').value || 10808),
  };
}

async function addNode(event) {
  event.preventDefault();
  setText('node-error', '');
  try {
    await api('/api/admin/nodes', { method: 'POST', body: buildNodePayload() });
    $('node-form').reset();
    $('node-kind').dispatchEvent(new Event('change'));
    await loadNodes();
  } catch (err) { setText('node-error', err.message); }
}

function syncNodeKindFields() {
  const kind = $('node-kind').value;
  $('proxy-fields').classList.toggle('hidden', kind !== 'proxy');
  $('xray-fields').classList.toggle('hidden', kind !== 'xray');
}

async function handleNodeAction(event) {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const id = button.getAttribute('data-id');
  const action = button.getAttribute('data-action');
  if (!id || !action) return;
  try {
    if (action === 'delete') {
      if (!window.confirm('确定删除该节点？')) return;
      await api(`/api/admin/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await loadNodes();
    } else if (action === 'toggle') {
      const node = state.nodes.find(item => item.id === id);
      if (!node) return;
      await api(`/api/admin/nodes/${encodeURIComponent(id)}`, { method: 'PATCH', body: { enabled: !node.enabled } });
      await loadNodes();
    } else if (action === 'xray') {
      const config = await api(`/api/admin/xray/config/${encodeURIComponent(id)}`);
      const output = $('xray-config-output');
      output.textContent = JSON.stringify(config, null, 2);
      output.classList.remove('hidden');
      downloadBlob(`${id}-xray.json`, JSON.stringify(config, null, 2), 'application/json');
    }
  } catch (err) { setText('node-error', err.message); }
}

async function loadSessions() {
  const data = await api('/api/admin/sessions');
  state.sessions = data.sessions || [];
  setText('max-devices', `最大并发设备：${data.maxConcurrentDevices ?? '-'}`);
  renderSessions();
}

function sessionStateLabel(s) {
  switch (s.state) {
    case 'active': return '活跃';
    case 'pending': return '待安装';
    case 'revoked': return '已撤销';
    case 'expired': return '已过期/空闲';
    default: return s.state;
  }
}

function renderSessions() {
  const body = $('sessions-body');
  if (!body) return;
  body.innerHTML = '';
  if (state.sessions.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="muted">暂无会话</td></tr>';
    return;
  }
  state.sessions.forEach(session => {
    const tr = document.createElement('tr');
    const revoke = session.state === 'active' || session.state === 'pending'
      ? `<button class="danger small" data-action="revoke" data-id="${escapeHtml(session.id)}">撤销</button>` : '-';
    tr.innerHTML = `
      <td class="mono">${escapeHtml(session.deviceId)}</td>
      <td class="mono">${escapeHtml(session.ip || '-')}</td>
      <td>${escapeHtml(session.nodeName)}</td>
      <td>${sessionStateLabel(session)}${session.enrolled ? ' · 已绑定' : ''}</td>
      <td>${session.remainingSeconds > 0 ? fmtRemaining(session.remainingSeconds) : '-'}</td>
      <td>${fmtTime(session.expiresAt)}</td>
      <td>${revoke}</td>`;
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
  } catch (err) { setText('admin-error', err.message); }
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
    setText('session-message', session ? `上次会话状态：${sessionStateLabel(session)}` : '选择节点和有效期后生成临时 CRX。');
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
  if (!nodeId) throw new Error('请先添加并启用一个代理节点');
  const ttlSeconds = Number($('ttl-select').value || 3600);
  const data = await api('/api/session', { method: 'POST', body: { deviceId: ensureDeviceId(), nodeId, ttlSeconds } });
  state.currentSession = data.session;
  renderCurrentSession();
  await loadSessions();
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
    await loadSessions();
  } catch (err) { setText('session-message', err.message); }
}

async function loadSecurity() {
  try {
    const data = await api('/api/admin/settings');
    state.authSettings = data;
    $('auth-mode').value = data.authMode;
    $('totp-qr').src = data.qrDataUrl;
    setText('totp-uri', `${data.otpauthUri}\n密钥：${data.totpSecretBase32}`);
  } catch (err) { console.error('security', err); }
  try {
    const bans = await api('/api/admin/login-bans');
    state.bans = bans.bans || [];
    setText('ban-config', `按 ${bans.config.key} 计数：${bans.config.windowSeconds}s 内失败 ${bans.config.maxAttempts} 次 → 封禁 ${bans.config.banSeconds}s（可在下方手动解封）`);
    renderBans();
  } catch (err) { console.error('bans', err); }
}

function renderBans() {
  const body = $('bans-body');
  if (!body) return;
  body.innerHTML = '';
  if (state.bans.length === 0) {
    body.innerHTML = '<tr><td colspan="4" class="muted">当前没有被封禁的 IP</td></tr>';
    return;
  }
  state.bans.forEach(ban => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${escapeHtml(ban.ip)}</td>
      <td>${fmtTime(ban.bannedUntil)}</td>
      <td>${fmtTime(ban.lastFailureAt)}</td>
      <td><button class="secondary small" data-action="unban" data-ip="${escapeHtml(ban.ip)}">解封</button></td>`;
    body.appendChild(tr);
  });
}

async function handleBanAction(event) {
  const button = event.target.closest('button[data-action="unban"]');
  if (!button) return;
  const ip = button.getAttribute('data-ip');
  if (!ip) return;
  try {
    await api(`/api/admin/login-bans/${encodeURIComponent(ip)}`, { method: 'DELETE' });
    await loadSecurity();
  } catch (err) { setText('security-message', err.message); }
}

async function saveAuthMode() {
  setText('security-message', '');
  try {
    await api('/api/admin/settings', { method: 'PATCH', body: { authMode: $('auth-mode').value } });
    setText('security-message', '认证方式已保存');
    await loadSecurity();
  } catch (err) { setText('security-message', err.message); }
}

async function savePassword() {
  setText('security-message', '');
  try {
    await api('/api/admin/settings/password', { method: 'POST', body: { password: $('new-password').value } });
    if ($('new-password')) $('new-password').value = '';
    setText('security-message', '密码已设置');
    await loadSecurity();
  } catch (err) { setText('security-message', err.message); }
}

async function clearPassword() {
  setText('security-message', '');
  try {
    await api('/api/admin/settings/password', { method: 'DELETE' });
    setText('security-message', '密码已清除，认证方式已回退为仅 TOTP');
    await loadSecurity();
  } catch (err) { setText('security-message', err.message); }
}

async function regenerateTotp() {
  setText('security-message', '');
  try {
    await api('/api/admin/settings/totp/regenerate', { method: 'POST', body: { currentTotp: $('current-totp').value.trim() } });
    if ($('current-totp')) $('current-totp').value = '';
    setText('security-message', '已生成新的随机密钥，请重新扫码绑定');
    await loadSecurity();
  } catch (err) { setText('security-message', err.message); }
}

async function importLinks() {
  setText('xray-message', '');
  try {
    const text = $('xray-links').value;
    const result = await api('/api/admin/nodes/import', { method: 'POST', body: { text } });
    setText('xray-message', `导入成功 ${result.importedCount} 个，失败 ${result.errorCount} 个`);
    $('xray-links').value = '';
    await loadNodes();
    renderXray();
  } catch (err) { setText('xray-message', err.message); }
}

async function exportLinks() {
  try {
    const data = await api('/api/admin/nodes/export/links');
    $('xray-links').value = (data.links || []).join('\n');
    setText('xray-message', `已导出 ${data.links.length} 条链接到文本框`);
  } catch (err) { setText('xray-message', err.message); }
}

function renderXray() {
  const body = $('xray-body');
  if (!body) return;
  body.innerHTML = '';
  const xrayNodes = state.nodes.filter(node => node.kind === 'xray');
  if (xrayNodes.length === 0) {
    body.innerHTML = '<tr><td colspan="6" class="muted">暂无 Xray 节点</td></tr>';
    return;
  }
  xrayNodes.forEach(node => {
    const x = node.xray || {};
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(node.name)}</td>
      <td>${escapeHtml(x.protocol || '')}</td>
      <td class="mono">${escapeHtml(node.host)}:${escapeHtml(node.port)}</td>
      <td>${escapeHtml(x.network || 'tcp')} / ${escapeHtml(x.security || 'none')}</td>
      <td class="mono">${escapeHtml(node.localScheme || 'socks5')}://${escapeHtml(node.localHost || '127.0.0.1')}:${escapeHtml(node.localPort || 10808)}</td>
      <td><button class="secondary small" data-action="xray" data-id="${escapeHtml(node.id)}">导出 Xray 配置</button></td>`;
    body.appendChild(tr);
  });
}

async function handleXrayTableAction(event) {
  const button = event.target.closest('button[data-action="xray"]');
  if (!button) return;
  const id = button.getAttribute('data-id');
  if (!id) return;
  try {
    const config = await api(`/api/admin/xray/config/${encodeURIComponent(id)}`);
    downloadBlob(`${id}-xray.json`, JSON.stringify(config, null, 2), 'application/json');
  } catch (err) { setText('xray-message', err.message); }
}

async function importEverything() {
  const output = $('import-result');
  output.classList.remove('hidden');
  output.textContent = '导入中…';
  try {
    const result = await api('/api/admin/nodes/import', { method: 'POST', body: { text: $('import-text').value } });
    output.textContent = JSON.stringify(result, null, 2);
    await loadNodes();
    renderXray();
  } catch (err) { output.textContent = err.message; }
}

function exportJson() {
  const includeSecrets = $('export-secrets').checked;
  fetch(`/api/admin/nodes/export?secrets=${includeSecrets ? 'true' : 'false'}`, { credentials: 'same-origin' })
    .then(r => r.text())
    .then(text => {
      $('export-preview').classList.remove('hidden');
      $('export-preview').textContent = text.slice(0, 4000);
      downloadBlob('redproxy-nodes.json', text, 'application/json');
    })
    .catch(err => { $('export-preview').classList.remove('hidden'); $('export-preview').textContent = String(err); });
}

async function exportShareLinksDownload() {
  try {
    const data = await api('/api/admin/nodes/export/links');
    downloadBlob('redproxy-nodes.txt', (data.links || []).join('\n'), 'text/plain');
  } catch (err) { setText('xray-message', err.message); }
}

async function loadLogs() {
  try {
    const data = await api('/api/admin/events');
    state.logs = data.events || [];
    renderLogs();
  } catch (err) { console.error('logs', err); }
}

function renderLogs() {
  const body = $('logs-body');
  if (!body) return;
  body.innerHTML = '';
  if (state.logs.length === 0) {
    body.innerHTML = '<tr><td colspan="6" class="muted">暂无日志</td></tr>';
    return;
  }
  state.logs.forEach(event => {
    const tr = document.createElement('tr');
    const detail = event.reason || (event.meta ? JSON.stringify(event.meta) : '');
    tr.innerHTML = `
      <td>${fmtTime(event.at)}</td>
      <td class="mono">${escapeHtml(event.type)}</td>
      <td class="mono">${escapeHtml(event.sessionId ? event.sessionId.slice(0, 8) : '-')}</td>
      <td>${escapeHtml(event.nodeId || '-')}</td>
      <td class="mono">${escapeHtml(event.ip || '-')}</td>
      <td class="small">${escapeHtml(detail)}</td>`;
    body.appendChild(tr);
  });
}

function switchTab(tab) {
  state.activeTab = tab;
  document.querySelectorAll('#tabs .tab').forEach(button => button.classList.toggle('active', button.getAttribute('data-tab') === tab));
  document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.toggle('hidden', panel.getAttribute('data-panel') !== tab));
  if (tab === 'security') void loadSecurity();
  if (tab === 'logs') void loadLogs();
  if (tab === 'sessions') void loadSessions();
  if (tab === 'xray') renderXray();
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
  pollTimer = setInterval(() => {
    tick();
    if (state.authenticated) { void loadSessions(); if (state.activeTab === 'logs') void loadLogs(); }
  }, 5000);
}

function pagehideRevoke() {
  const session = state.currentSession;
  if (!session || (session.state !== 'active' && session.state !== 'pending')) return;
  try {
    const payload = new Blob([JSON.stringify({ reason: 'pagehide' })], { type: 'application/json' });
    navigator.sendBeacon('/api/session/revoke', payload);
  } catch (err) { console.error('sendBeacon failed', err); }
}

function initEvents() {
  $('login-form').addEventListener('submit', login);
  $('logout-button').addEventListener('click', logout);
  $('tabs').addEventListener('click', event => {
    const button = event.target.closest('button[data-tab]');
    if (button) switchTab(button.getAttribute('data-tab'));
  });
  $('node-kind').addEventListener('change', syncNodeKindFields);
  $('node-form').addEventListener('submit', addNode);
  $('nodes-body').addEventListener('click', handleNodeAction);
  $('sessions-body').addEventListener('click', handleSessionAction);
  $('bans-body').addEventListener('click', handleBanAction);
  $('generate-crx').addEventListener('click', generateCrx);
  $('download-zip').addEventListener('click', downloadZip);
  $('close-session').addEventListener('click', revokeSession);
  $('save-auth-mode').addEventListener('click', saveAuthMode);
  $('save-password').addEventListener('click', savePassword);
  $('clear-password').addEventListener('click', clearPassword);
  $('regenerate-totp').addEventListener('click', regenerateTotp);
  $('import-links').addEventListener('click', importLinks);
  $('export-links').addEventListener('click', exportLinks);
  $('xray-body').addEventListener('click', handleXrayTableAction);
  $('import-button').addEventListener('click', importEverything);
  $('export-json').addEventListener('click', exportJson);
  $('export-links-button').addEventListener('click', exportShareLinksDownload);
  $('refresh-logs').addEventListener('click', loadLogs);
  window.addEventListener('pagehide', pagehideRevoke);
  window.addEventListener('beforeunload', pagehideRevoke);
}

document.addEventListener('DOMContentLoaded', () => {
  initEvents();
  syncNodeKindFields();
  void checkAuth();
});
