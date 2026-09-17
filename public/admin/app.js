'use strict';

const state = {
  authenticated: false,
  authMode: 'password',
  nodes: [],
  sessions: [],
  logs: [],
  bans: [],
  settings: null,
  activeTab: 'nodes',
  mustChangePassword: false,
};

let pollTimer = null;

const $ = id => document.getElementById(id);
const setText = (id, value) => { const el = $(id); if (el) el.textContent = value; };
const toggle = (id, hidden) => { const el = $(id); if (el) el.classList.toggle('hidden', hidden); };

function esc(value) {
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

function download(filename, content, type) {
  const blob = new Blob([content], { type: type || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function showAlert(id, message) {
  const el = $(id);
  if (!el) return;
  el.textContent = message;
  el.classList.toggle('hidden', !message);
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
    if (response.status === 401 && state.authenticated) setAuthenticated(false);
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
    setText('login-hint',
      data.passwordRequired && data.totpRequired ? '请输入用户名、密码和动态验证码。'
        : data.passwordRequired ? '请输入用户名和密码。'
          : '请输入动态验证码。');
  } catch (err) { console.error('auth mode', err); }
}

async function loadDefaultHint() {
  try {
    const settings = await api('/api/settings').catch(() => null);
    if (settings && settings.defaults) {
      setText('default-hint', `首次部署默认账号：${settings.defaults.username} / ${settings.defaults.password}，登录后请立即修改。`);
    }
  } catch (_err) { /* not logged in yet */ }
}

async function login(event) {
  event.preventDefault();
  showAlert('login-error', '');
  try {
    const data = await api('/api/auth/totp', {
      method: 'POST',
      body: {
        username: $('username-field').classList.contains('hidden') ? undefined : $('username').value.trim(),
        password: $('password-field').classList.contains('hidden') ? undefined : $('password').value,
        token: $('totp-field').classList.contains('hidden') ? undefined : $('totp-token').value.trim(),
      },
    });
    state.mustChangePassword = Boolean(data.mustChangePassword);
    setAuthenticated(true);
    await refreshAll();
    startPolling();
  } catch (err) {
    const details = err.data && err.data.details;
    let suffix = '';
    if (details && typeof details.attemptsRemaining === 'number') suffix = `（剩余尝试：${details.attemptsRemaining}）`;
    if (details && details.banned) suffix = `（IP 已临时封禁，请 ${details.retryAfterSeconds}s 后再试）`;
    showAlert('login-error', `${err.message}${suffix}`);
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
  await loadDefaultHint();
  try {
    const me = await api('/api/me');
    state.mustChangePassword = Boolean(me.mustChangePassword);
    setAuthenticated(true);
    await refreshAll();
    startPolling();
  } catch (err) {
    if (err.status !== 401) console.error(err);
    setAuthenticated(false);
  }
}

async function refreshAll() {
  await Promise.all([loadNodes(), loadSessions(), loadSecurity(), loadLogs()]);
}

// ------------------------------------------------------------------ nodes
async function loadNodes() {
  const data = await api('/api/nodes');
  state.nodes = data.nodes || [];
  renderNodes();
  renderXray();
}

function nodeLocalAddress(node) {
  if (node.kind !== 'xray') return `${node.scheme}://${node.host}:${node.port}`;
  return `${node.localScheme || 'socks5'}://${node.localHost || '127.0.0.1'}:${node.localPort || 10808}`;
}

function renderNodes() {
  const body = $('nodes-body');
  body.innerHTML = '';
  if (state.nodes.length === 0) {
    body.innerHTML = '<tr><td colspan="6" class="empty">暂无节点</td></tr>';
    return;
  }
  state.nodes.forEach(node => {
    const tr = document.createElement('tr');
    const type = node.kind === 'xray' ? `Xray · ${node.xray ? node.xray.protocol : '?'}` : node.scheme;
    tr.innerHTML = `
      <td>${esc(node.name)}</td>
      <td>${esc(type)}</td>
      <td class="mono">${esc(node.host)}:${esc(node.port)}</td>
      <td class="mono">${esc(nodeLocalAddress(node))}</td>
      <td>${node.enabled ? '<span class="ok">启用</span>' : '<span class="muted">停用</span>'}</td>
      <td class="row-actions">
        <button class="btn ghost small" data-action="toggle" data-id="${esc(node.id)}">${node.enabled ? '停用' : '启用'}</button>
        ${node.kind === 'xray' ? `<button class="btn ghost small" data-action="xray" data-id="${esc(node.id)}">导出配置</button>` : ''}
        <button class="btn danger small" data-action="delete" data-id="${esc(node.id)}">删除</button>
      </td>`;
    body.appendChild(tr);
  });
}

function syncNodeKindFields() {
  const kind = $('node-kind').value;
  toggle('proxy-fields', kind !== 'proxy');
  toggle('xray-fields', kind !== 'xray');
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
  return {
    kind, name, enabled,
    scheme: 'socks5',
    host: $('xray-host').value.trim(),
    port: Number($('xray-port').value),
    username: null,
    password: null,
    xray: {
      protocol: $('xray-protocol').value,
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
    },
    localScheme: $('local-scheme').value,
    localHost: $('local-host').value.trim() || '127.0.0.1',
    localPort: Number($('local-port').value || 10808),
  };
}

async function addNode(event) {
  event.preventDefault();
  showAlert('node-error', '');
  try {
    await api('/api/nodes', { method: 'POST', body: buildNodePayload() });
    $('node-form').reset();
    syncNodeKindFields();
    await loadNodes();
  } catch (err) { showAlert('node-error', err.message); }
}

async function handleNodeAction(event) {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const id = button.getAttribute('data-id');
  const action = button.getAttribute('data-action');
  try {
    if (action === 'delete') {
      if (!window.confirm('确定删除该节点？')) return;
      await api(`/api/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await loadNodes();
    } else if (action === 'toggle') {
      const node = state.nodes.find(n => n.id === id);
      if (!node) return;
      await api(`/api/nodes/${encodeURIComponent(id)}`, { method: 'PATCH', body: { enabled: !node.enabled } });
      await loadNodes();
    } else if (action === 'xray') {
      const config = await api(`/api/xray/config/${encodeURIComponent(id)}`);
      const output = $('xray-config-output');
      output.textContent = JSON.stringify(config, null, 2);
      output.classList.remove('hidden');
      download(`${id}-xray.json`, JSON.stringify(config, null, 2), 'application/json');
    }
  } catch (err) { showAlert('node-error', err.message); }
}

// ------------------------------------------------------------------ sessions
async function loadSessions() {
  const data = await api('/api/sessions');
  state.sessions = data.sessions || [];
  setText('max-devices', `最大并发设备 ${data.maxConcurrentDevices ?? '-'}`);
  const body = $('sessions-body');
  body.innerHTML = '';
  if (state.sessions.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="empty">暂无会话</td></tr>';
    return;
  }
  state.sessions.forEach(session => {
    const active = session.state === 'active' || session.state === 'pending';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${esc(session.deviceId)}</td>
      <td class="mono">${esc(session.ip || '-')}</td>
      <td>${esc(session.nodeName)}</td>
      <td>${esc(session.state)}${session.enrolled ? ' · 已绑定' : ''}</td>
      <td>${session.remainingSeconds > 0 ? fmtRemaining(session.remainingSeconds) : '-'}</td>
      <td>${fmtTime(session.expiresAt)}</td>
      <td class="row-actions">${active ? `<button class="btn danger small" data-action="revoke" data-id="${esc(session.id)}">撤销</button>` : ''}</td>`;
    body.appendChild(tr);
  });
}

async function handleSessionAction(event) {
  const button = event.target.closest('button[data-action="revoke"]');
  if (!button) return;
  try {
    await api(`/api/sessions/${encodeURIComponent(button.getAttribute('data-id'))}`, { method: 'DELETE' });
    await loadSessions();
  } catch (err) { showAlert('admin-error', err.message); }
}

// ------------------------------------------------------------------ security
async function loadSecurity() {
  try {
    const data = await api('/api/settings');
    state.settings = data;
    $('admin-auth-mode').value = data.adminAuthMode;
    $('user-auth-mode').value = data.userAuthMode;
    $('username-input').value = data.username;
    if (data.qrDataUrl) {
      $('totp-qr').src = data.qrDataUrl;
      $('totp-qr').classList.remove('hidden');
      setText('totp-uri', data.otpauthUri || '');
    } else {
      $('totp-qr').classList.add('hidden');
      setText('totp-uri', '尚未生成 TOTP 密钥');
    }
    if (data.mustChangePassword) {
      toggle('force-change', false);
      toggle('admin-body', true);
    } else {
      toggle('force-change', true);
      toggle('admin-body', false);
    }
  } catch (err) { console.error('security', err); }

  try {
    const bans = await api('/api/login-bans');
    state.bans = bans.bans || [];
    setText('ban-config', `${bans.config.windowSeconds}s 内失败 ${bans.config.maxAttempts} 次 → 封禁 ${bans.config.banSeconds}s（按 ${bans.config.key}）`);
    const body = $('bans-body');
    body.innerHTML = '';
    if (state.bans.length === 0) {
      body.innerHTML = '<tr><td colspan="4" class="empty">当前没有封禁</td></tr>';
    } else {
      state.bans.forEach(ban => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="mono">${esc(ban.ip)}</td>
          <td>${fmtTime(ban.bannedUntil)}</td>
          <td>${fmtTime(ban.lastFailureAt)}</td>
          <td class="row-actions"><button class="btn ghost small" data-action="unban" data-ip="${esc(ban.ip)}">解封</button></td>`;
        body.appendChild(tr);
      });
    }
  } catch (err) { console.error('bans', err); }
}

async function handleBanAction(event) {
  const button = event.target.closest('button[data-action="unban"]');
  if (!button) return;
  try {
    await api(`/api/login-bans/${encodeURIComponent(button.getAttribute('data-ip'))}`, { method: 'DELETE' });
    await loadSecurity();
  } catch (err) { showAlert('security-message', err.message); }
}

async function saveModes() {
  showAlert('security-message', '');
  try {
    await api('/api/settings', {
      method: 'PATCH',
      body: { adminAuthMode: $('admin-auth-mode').value, userAuthMode: $('user-auth-mode').value },
    });
    showAlert('security-message', '登录方式已保存');
    await Promise.all([loadSecurity(), loadAuthMode()]);
  } catch (err) { showAlert('security-message', err.message); }
}

async function saveAccount() {
  showAlert('security-message', '');
  const username = $('username-input').value.trim();
  const password = $('new-password').value;
  const confirm = $('new-password-confirm').value;
  if (password && password !== confirm) {
    showAlert('security-message', '两次输入的密码不一致');
    return;
  }
  try {
    if (username) await api('/api/settings', { method: 'PATCH', body: { username } });
    if (password) await api('/api/settings/password', { method: 'POST', body: { password } });
    $('new-password').value = '';
    $('new-password-confirm').value = '';
    showAlert('security-message', '账号已更新');
    await loadSecurity();
  } catch (err) { showAlert('security-message', err.message); }
}

async function forceChangePassword(event) {
  event.preventDefault();
  showAlert('force-error', '');
  const password = $('force-password').value;
  const confirm = $('force-password-confirm').value;
  if (password !== confirm) { showAlert('force-error', '两次输入的密码不一致'); return; }
  try {
    await api('/api/settings/password', { method: 'POST', body: { password } });
    $('force-password').value = '';
    $('force-password-confirm').value = '';
    state.mustChangePassword = false;
    await loadSecurity();
  } catch (err) { showAlert('force-error', err.message); }
}

async function clearPassword() {
  showAlert('security-message', '');
  try {
    await api('/api/settings/password', { method: 'DELETE' });
    showAlert('security-message', '密码已清除，依赖密码的登录方式已自动回退为仅 TOTP');
    await Promise.all([loadSecurity(), loadAuthMode()]);
  } catch (err) { showAlert('security-message', err.message); }
}

async function regenerateTotp() {
  showAlert('security-message', '');
  try {
    await api('/api/settings/totp/regenerate', { method: 'POST', body: { currentTotp: $('current-totp').value.trim() } });
    $('current-totp').value = '';
    showAlert('security-message', '已生成新密钥，请重新扫码绑定');
    await loadSecurity();
  } catch (err) { showAlert('security-message', err.message); }
}

// ------------------------------------------------------------------ xray / transfer
async function importLinks() {
  setText('xray-message', '');
  try {
    const result = await api('/api/nodes/import', { method: 'POST', body: { text: $('xray-links').value } });
    setText('xray-message', `导入 ${result.importedCount} 个，失败 ${result.errorCount} 个`);
    $('xray-links').value = '';
    await loadNodes();
  } catch (err) { setText('xray-message', err.message); }
}

async function exportLinks() {
  try {
    const data = await api('/api/nodes/export/links');
    $('xray-links').value = (data.links || []).join('\n');
    setText('xray-message', `已导出 ${data.links.length} 条`);
  } catch (err) { setText('xray-message', err.message); }
}

function renderXray() {
  const body = $('xray-body');
  body.innerHTML = '';
  const list = state.nodes.filter(node => node.kind === 'xray');
  if (list.length === 0) {
    body.innerHTML = '<tr><td colspan="6" class="empty">暂无 Xray 节点</td></tr>';
    return;
  }
  list.forEach(node => {
    const x = node.xray || {};
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${esc(node.name)}</td>
      <td>${esc(x.protocol || '')}</td>
      <td class="mono">${esc(node.host)}:${esc(node.port)}</td>
      <td>${esc(x.network || 'tcp')} / ${esc(x.security || 'none')}</td>
      <td class="mono">${esc(node.localScheme || 'socks5')}://${esc(node.localHost || '127.0.0.1')}:${esc(node.localPort || 10808)}</td>
      <td class="row-actions"><button class="btn ghost small" data-action="xray" data-id="${esc(node.id)}">导出配置</button></td>`;
    body.appendChild(tr);
  });
}

async function handleXrayAction(event) {
  const button = event.target.closest('button[data-action="xray"]');
  if (!button) return;
  try {
    const config = await api(`/api/xray/config/${encodeURIComponent(button.getAttribute('data-id'))}`);
    download(`${button.getAttribute('data-id')}-xray.json`, JSON.stringify(config, null, 2), 'application/json');
  } catch (err) { setText('xray-message', err.message); }
}

async function importEverything() {
  const output = $('import-result');
  output.classList.remove('hidden');
  output.textContent = '导入中…';
  try {
    const result = await api('/api/nodes/import', { method: 'POST', body: { text: $('import-text').value } });
    output.textContent = JSON.stringify(result, null, 2);
    await loadNodes();
  } catch (err) { output.textContent = err.message; }
}

async function exportJson() {
  try {
    const includeSecrets = $('export-secrets').checked;
    const response = await fetch(`/api/nodes/export?secrets=${includeSecrets}`, { credentials: 'same-origin' });
    const text = await response.text();
    $('export-preview').classList.remove('hidden');
    $('export-preview').textContent = text.slice(0, 4000);
    download('redproxy-nodes.json', text, 'application/json');
  } catch (err) {
    $('export-preview').classList.remove('hidden');
    $('export-preview').textContent = String(err);
  }
}

async function exportLinksDownload() {
  try {
    const data = await api('/api/nodes/export/links');
    download('redproxy-nodes.txt', (data.links || []).join('\n'), 'text/plain');
  } catch (err) { setText('xray-message', err.message); }
}

// ------------------------------------------------------------------ logs
async function loadLogs() {
  try {
    const data = await api('/api/events');
    state.logs = data.events || [];
    const body = $('logs-body');
    body.innerHTML = '';
    if (state.logs.length === 0) {
      body.innerHTML = '<tr><td colspan="6" class="empty">暂无日志</td></tr>';
      return;
    }
    state.logs.forEach(event => {
      const tr = document.createElement('tr');
      const detail = event.reason || (event.meta ? JSON.stringify(event.meta) : '');
      tr.innerHTML = `
        <td>${fmtTime(event.at)}</td>
        <td class="mono">${esc(event.type)}</td>
        <td class="mono">${esc(event.sessionId ? event.sessionId.slice(0, 8) : '-')}</td>
        <td>${esc(event.nodeId || '-')}</td>
        <td class="mono">${esc(event.ip || '-')}</td>
        <td class="small">${esc(detail)}</td>`;
      body.appendChild(tr);
    });
  } catch (err) { console.error('logs', err); }
}

// ------------------------------------------------------------------ ui
const HELP = {
  nodes: '<p>传统代理由扩展直连 <code>http/https/socks4/socks5</code>。Xray 节点需要你在服务器上运行 Xray，导出配置后启动本地 Inbound，扩展连接的是本地 Inbound。</p>',
  xray: '<p>支持每行一条：</p><ul><li><code>vless://uuid@host:port?...#name</code></li><li><code>vmess://base64(json)</code></li><li><code>trojan://password@host:port?...#name</code></li><li><code>ss://base64(method:password)@host:port#name</code>（SIP002 与旧版）</li><li><code>http(s)://</code>、<code>socks4://</code>、<code>socks5://</code> 代理链接</li></ul>',
  transfer: '<p>导入支持 RedProxy JSON 数组、<code>{nodes:[...]}</code> 或每行一条分享链接。导出 JSON 可选择是否包含密码/凭据，包含凭据时请妥善保管。</p>',
};

function openHelp(key) {
  setText('modal-title', key === 'nodes' ? '节点说明' : key === 'xray' ? '支持的分享链接' : '导入导出说明');
  $('modal-body').innerHTML = HELP[key] || '';
  toggle('modal', false);
}

function switchTab(tab) {
  state.activeTab = tab;
  document.querySelectorAll('#tabs .tab').forEach(b => b.classList.toggle('active', b.getAttribute('data-tab') === tab));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('hidden', p.getAttribute('data-panel') !== tab));
  if (tab === 'security') void loadSecurity();
  if (tab === 'logs') void loadLogs();
  if (tab === 'sessions') void loadSessions();
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    if (!state.authenticated || state.mustChangePassword) return;
    void loadSessions();
    if (state.activeTab === 'logs') void loadLogs();
  }, 5000);
}

document.addEventListener('DOMContentLoaded', () => {
  $('login-form').addEventListener('submit', login);
  $('logout-button').addEventListener('click', logout);
  $('force-password-form').addEventListener('submit', forceChangePassword);
  $('tabs').addEventListener('click', event => {
    const button = event.target.closest('button[data-tab]');
    if (button) switchTab(button.getAttribute('data-tab'));
  });
  document.body.addEventListener('click', event => {
    const help = event.target.closest('button[data-help]');
    if (help) openHelp(help.getAttribute('data-help'));
  });
  $('modal-close').addEventListener('click', () => toggle('modal', true));
  $('modal').addEventListener('click', event => { if (event.target === $('modal')) toggle('modal', true); });
  $('node-kind').addEventListener('change', syncNodeKindFields);
  $('node-form').addEventListener('submit', addNode);
  $('nodes-body').addEventListener('click', handleNodeAction);
  $('sessions-body').addEventListener('click', handleSessionAction);
  $('bans-body').addEventListener('click', handleBanAction);
  $('save-modes').addEventListener('click', saveModes);
  $('save-password').addEventListener('click', saveAccount);
  $('clear-password').addEventListener('click', clearPassword);
  $('regenerate-totp').addEventListener('click', regenerateTotp);
  $('import-links').addEventListener('click', importLinks);
  $('export-links').addEventListener('click', exportLinks);
  $('xray-body').addEventListener('click', handleXrayAction);
  $('import-button').addEventListener('click', importEverything);
  $('export-json').addEventListener('click', exportJson);
  $('export-links-button').addEventListener('click', exportLinksDownload);
  $('refresh-logs').addEventListener('click', loadLogs);
  syncNodeKindFields();
  void checkAuth();
});
