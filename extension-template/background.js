/* global chrome, fetch, AbortController, setTimeout, clearTimeout, setInterval, clearInterval */
/**
 * RedProxy one-time temporary proxy extension.
 *
 * The server replaces __REDPROXY_CONFIG__ with a JSON object before packing this
 * file into the CRX3. The injected token is short-lived, bound to one server
 * session and one proxy node.
 */
(function initRedProxy(root) {
  'use strict';

  var CONFIG = __REDPROXY_CONFIG__;
  var IS_TEST = typeof globalThis !== 'undefined' && globalThis.__REDPROXY_TEST__ === true;
  var HEARTBEAT_INTERVAL_MS = 15000;
  var ALARM_NAME = 'redproxy-heartbeat';
  var STORAGE_KEYS = {
    originalProxy: 'redproxy_original_proxy',
    config: 'redproxy_runtime_config',
    lastHeartbeat: 'redproxy_last_heartbeat',
    expiresAt: 'redproxy_expires_at',
    applied: 'redproxy_temp_applied',
    accessToken: 'redproxy_access_token'
  };

  var cleanupPromise = null;
  var cleanupFinished = false;
  var heartbeatTimer = null;
  var heartbeatFailures = 0;
  var authHandlerInstalled = false;
  var state = {
    originalProxy: null,
    tempApplied: false,
    lastHeartbeatAt: 0,
    expiresAt: CONFIG && CONFIG.expiresAt ? CONFIG.expiresAt : 0,
    alive: true,
    reason: null
  };

  function log() {
    try {
      console.log.apply(console, ['[RedProxy]'].concat(Array.prototype.slice.call(arguments)));
    } catch (_err) {
      // Never let logging break cleanup.
    }
  }

  function warn() {
    try {
      console.warn.apply(console, ['[RedProxy]'].concat(Array.prototype.slice.call(arguments)));
    } catch (_err) {
      // Ignore.
    }
  }

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  function storageGet(keys) {
    return new Promise(function (resolve, reject) {
      try {
        chrome.storage.local.get(keys, function (items) {
          var error = chrome.runtime && chrome.runtime.lastError;
          if (error) reject(new Error(error.message));
          else resolve(items || {});
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  function storageSet(items) {
    return new Promise(function (resolve, reject) {
      try {
        chrome.storage.local.set(items, function () {
          var error = chrome.runtime && chrome.runtime.lastError;
          if (error) reject(new Error(error.message));
          else resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  function storageRemove(keys) {
    return new Promise(function (resolve, reject) {
      try {
        chrome.storage.local.remove(keys, function () {
          var error = chrome.runtime && chrome.runtime.lastError;
          if (error) reject(new Error(error.message));
          else resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  function proxyGet() {
    return new Promise(function (resolve, reject) {
      try {
        chrome.proxy.settings.get({ incognito: false }, function (details) {
          if (details && details.value) resolve(details);
          else reject(new Error('proxy settings get returned no value'));
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  function proxySet(details) {
    return new Promise(function (resolve, reject) {
      try {
        chrome.proxy.settings.set(details, function () {
          var error = chrome.runtime && chrome.runtime.lastError;
          if (error) reject(new Error(error.message));
          else resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  function uninstallSelf() {
    return new Promise(function (resolve) {
      try {
        if (!chrome.management || typeof chrome.management.uninstallSelf !== 'function') {
          resolve();
          return;
        }
        chrome.management.uninstallSelf({ showConfirmDialog: false }, function () { resolve(); });
      } catch (_err) {
        resolve();
      }
    });
  }

  function buildProxyConfig(node) {
    var scheme = node && node.scheme ? node.scheme : 'http';
    if (scheme !== 'http' && scheme !== 'https' && scheme !== 'socks4' && scheme !== 'socks5') {
      scheme = 'http';
    }
    return {
      mode: 'fixed_servers',
      rules: {
        singleProxy: {
          scheme: scheme,
          host: node.host,
          port: node.port
        },
        bypassList: ['<local>']
      }
    };
  }

  async function saveOriginalProxy() {
    var details = await proxyGet();
    var original = {
      value: details.value,
      levelOfControl: details.levelOfControl || null,
      scope: 'regular'
    };
    state.originalProxy = original;
    await storageSet({ [STORAGE_KEYS.originalProxy]: original });
    log('saved original proxy settings');
    return original;
  }

  async function applyProxy() {
    var proxyConfig = buildProxyConfig(CONFIG.node);
    await proxySet({ value: proxyConfig, scope: 'regular' });
    state.tempApplied = true;
    await storageSet({ [STORAGE_KEYS.applied]: true });
    log('temporary proxy applied', CONFIG.node.id);
    return proxyConfig;
  }

  async function restoreOriginalProxy() {
    var items = await storageGet([STORAGE_KEYS.originalProxy]);
    var original = state.originalProxy || items[STORAGE_KEYS.originalProxy];
    if (!original || !original.value) {
      log('no original proxy settings to restore');
      state.tempApplied = false;
      await storageSet({ [STORAGE_KEYS.applied]: false });
      return false;
    }

    var lastError = null;
    for (var attempt = 0; attempt < 3; attempt += 1) {
      try {
        await proxySet({ value: original.value, scope: original.scope || 'regular' });
        state.originalProxy = null;
        state.tempApplied = false;
        await storageSet({ [STORAGE_KEYS.applied]: false });
        log('original proxy settings restored');
        return true;
      } catch (err) {
        lastError = err;
        warn('failed to restore original proxy settings, retrying', attempt + 1, err && err.message);
        await sleep(300 * (attempt + 1));
      }
    }

    state.tempApplied = false;
    await storageSet({ [STORAGE_KEYS.applied]: false });
    throw lastError || new Error('could not restore original proxy settings');
  }

  function installProxyAuthHandler() {
    if (authHandlerInstalled) return;
    if (!CONFIG.node || (!CONFIG.node.username && !CONFIG.node.password)) return;
    if (!chrome.webRequest || !chrome.webRequest.onAuthRequired) return;
    try {
      chrome.webRequest.onAuthRequired.addListener(
        function (details, callback) {
          if (!details || !details.isProxy) {
            callback({});
            return;
          }
          callback({
            authCredentials: {
              username: CONFIG.node.username || '',
              password: CONFIG.node.password || ''
            }
          });
        },
        { urls: ['<all_urls>'] },
        ['asyncBlocking']
      );
      authHandlerInstalled = true;
      log('proxy authentication handler installed');
    } catch (err) {
      warn('could not install proxy authentication handler', err && err.message);
    }
  }

  function stopHeartbeat() {
    if (heartbeatTimer !== null) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
    try {
      if (chrome.alarms) chrome.alarms.clear(ALARM_NAME);
    } catch (_err) {
      // Ignore alarm cleanup failures.
    }
  }

  function startHeartbeat() {
    stopHeartbeat();
    heartbeatTimer = setInterval(function () {
      heartbeat().catch(function (err) { warn('heartbeat task error', err && err.message); });
    }, HEARTBEAT_INTERVAL_MS);
    try {
      if (chrome.alarms) {
        chrome.alarms.create(ALARM_NAME, { periodInMinutes: HEARTBEAT_INTERVAL_MS / 60000 });
      }
    } catch (err) {
      warn('could not create heartbeat alarm', err && err.message);
    }
    log('heartbeat task started');
  }

  async function heartbeat() {
    if (cleanupFinished) return { ok: false };
    if (!CONFIG || !CONFIG.extensionToken || !CONFIG.serverUrl) {
      await cleanup('missing_runtime_config');
      return { ok: false };
    }

    var now = Date.now();
    if (now >= state.expiresAt) {
      await cleanup('local_expiry');
      return { ok: false };
    }

    var controller = typeof AbortController === 'function' ? new AbortController() : null;
    var timeout = null;
    try {
      if (controller) {
        timeout = setTimeout(function () { controller.abort(); }, 10000);
      }
      var response = await fetch(CONFIG.serverUrl + '/api/extension/heartbeat', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + CONFIG.extensionToken,
          'Content-Type': 'application/json'
        },
        body: '{}',
        signal: controller ? controller.signal : undefined
      });

      if (response.status === 401 || response.status === 403) {
        await cleanup('server_rejected');
        return { ok: false };
      }
      if (!response.ok) {
        heartbeatFailures += 1;
        warn('heartbeat returned non-OK status', response.status, heartbeatFailures);
        if (heartbeatFailures >= 3) await cleanup('heartbeat_failed');
        return { ok: false };
      }

      var data = {};
      try { data = await response.json(); } catch (_err) { data = {}; }
      if (data && data.revoked) {
        await cleanup('server_revoked');
        return { ok: false };
      }

      heartbeatFailures = 0;
      state.lastHeartbeatAt = Date.now();
      if (data && data.expiresAt) state.expiresAt = data.expiresAt;
      // The enrollment token embedded in the CRX is single-use. The server
      // rotates it on first heartbeat (and on later heartbeats) and the rotated
      // token lives only in chrome.storage.local, never in the downloaded file.
      if (data && data.token && typeof data.token === 'string') {
        CONFIG.extensionToken = data.token;
        await storageSet({ [STORAGE_KEYS.accessToken]: data.token });
        log('rotated one-time extension token');
      }
      await storageSet({
        [STORAGE_KEYS.lastHeartbeat]: state.lastHeartbeatAt,
        [STORAGE_KEYS.expiresAt]: state.expiresAt
      });
      return { ok: true, data: data };
    } catch (err) {
      heartbeatFailures += 1;
      warn('heartbeat failed', heartbeatFailures, err && err.message);
      if (heartbeatFailures >= 3) await cleanup('heartbeat_failed');
      return { ok: false };
    } finally {
      if (timeout !== null) clearTimeout(timeout);
    }
  }

  async function doCleanup(reason) {
    if (cleanupFinished) return;
    cleanupFinished = true;
    state.alive = false;
    state.reason = reason;
    log('cleanup started', reason);

    stopHeartbeat();

    try {
      await fetch(CONFIG.serverUrl + '/api/extension/revoke', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + CONFIG.extensionToken },
        body: '{}'
      });
    } catch (err) {
      warn('server revoke failed during cleanup', err && err.message);
    }

    try {
      await restoreOriginalProxy();
    } catch (err) {
      warn('original proxy restore failed after retries', err && err.message);
    }

    try {
      await storageRemove([
        STORAGE_KEYS.originalProxy,
        STORAGE_KEYS.config,
        STORAGE_KEYS.lastHeartbeat,
        STORAGE_KEYS.expiresAt,
        STORAGE_KEYS.applied,
        STORAGE_KEYS.accessToken
      ]);
    } catch (err) {
      warn('local storage cleanup failed', err && err.message);
    }

    await uninstallSelf();
    log('cleanup finished', reason);
  }

  function cleanup(reason) {
    if (!cleanupPromise) {
      cleanupPromise = doCleanup(reason).catch(function (err) {
        warn('cleanup error', err && err.message);
      });
    }
    return cleanupPromise;
  }

  async function start() {
    if (cleanupFinished) return;
    if (!CONFIG || !CONFIG.extensionToken) {
      await cleanup('missing_runtime_config');
      return;
    }

    var stored = {};
    try {
      stored = await storageGet([
        STORAGE_KEYS.originalProxy,
        STORAGE_KEYS.lastHeartbeat,
        STORAGE_KEYS.expiresAt,
        STORAGE_KEYS.accessToken
      ]);
    } catch (err) {
      warn('could not read stored state', err && err.message);
    }

    if (stored[STORAGE_KEYS.accessToken] && typeof stored[STORAGE_KEYS.accessToken] === 'string') {
      // Reuse the rotated token from a previous service-worker lifetime. The
      // CRX-embedded enrollment token stays single-use and is never replayed.
      CONFIG.extensionToken = stored[STORAGE_KEYS.accessToken];
      log('reusing rotated access token');
    }

    state.originalProxy = state.originalProxy || stored[STORAGE_KEYS.originalProxy] || null;
    state.lastHeartbeatAt = stored[STORAGE_KEYS.lastHeartbeat] || 0;
    state.expiresAt = CONFIG.expiresAt || stored[STORAGE_KEYS.expiresAt] || 0;

    if (Date.now() >= state.expiresAt) {
      await cleanup('local_expiry');
      return;
    }

    if (!state.originalProxy) {
      await saveOriginalProxy();
    } else {
      log('reusing saved original proxy settings');
    }

    installProxyAuthHandler();
    await applyProxy();
    startHeartbeat();
    await heartbeat();
  }

  if (typeof chrome !== 'undefined') {
    try {
      if (chrome.runtime && chrome.runtime.onMessage) {
        chrome.runtime.onMessage.addListener(function (message, _sender, sendResponse) {
          if (message && message.type === 'REDPROXY_CLOSE') {
            cleanup('user_request').then(function () { sendResponse({ ok: true }); });
            return true;
          }
          return false;
        });
      }
      if (chrome.alarms && chrome.alarms.onAlarm) {
        chrome.alarms.onAlarm.addListener(function (alarm) {
          if (alarm && alarm.name === ALARM_NAME) {
            heartbeat().catch(function (err) { warn('alarm heartbeat error', err && err.message); });
          }
        });
      }
    } catch (err) {
      warn('could not register chrome listeners', err && err.message);
    }
  }

  var api = {
    start: start,
    heartbeat: heartbeat,
    cleanup: cleanup,
    buildProxyConfig: buildProxyConfig,
    saveOriginalProxy: saveOriginalProxy,
    applyProxy: applyProxy,
    restoreOriginalProxy: restoreOriginalProxy,
    installProxyAuthHandler: installProxyAuthHandler,
    _state: state
  };

  root.RedProxy = api;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  if (!IS_TEST) {
    start().catch(function (err) { warn('startup failed', err && err.message); });
  }
})(typeof self !== 'undefined' ? self : globalThis);
