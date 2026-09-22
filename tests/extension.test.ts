import path from 'node:path';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';
import { renderBackground } from '../server/src/extension';
import type { ExtensionRuntimeConfig } from '../server/src/types';

interface FetchCall {
  url: string;
  headers: Record<string, string>;
  body?: string;
}

function runtimeConfig(overrides: Partial<ExtensionRuntimeConfig> = {}): ExtensionRuntimeConfig {
  return {
    serverUrl: 'https://redproxy.example.com',
    extensionToken: 'initial-enrollment-token',
    sessionId: 'session-1',
    deviceId: 'device-1',
    expiresAt: Date.now() + 600000,
    generatedAt: Date.now(),
    heartbeatIntervalSeconds: 15,
    enrollmentExpiresAt: Date.now() + 120000,
    idleSeconds: 90,
    proxyMode: 'direct',
    proxy: null,
    node: { id: 'tokyo-1', name: 'Tokyo', scheme: 'socks5', host: '127.0.0.1', port: 10809, username: null, password: null },
    ...overrides,
  };
}

function createChrome(originalValue: unknown) {
  const storage: Record<string, unknown> = {};
  const setCalls: Array<{ value: unknown; scope?: string }> = [];
  let currentValue = originalValue;
  let failFirstSets = 0;

  const chrome: Record<string, any> = {
    proxy: {
      settings: {
        get: (_details: unknown, callback: (value: unknown) => void) => callback({ value: currentValue, levelOfControl: 'controllable_by_this_extension' }),
        set: (details: { value: unknown; scope?: string }, callback: () => void) => {
          if (failFirstSets > 0) {
            failFirstSets -= 1;
            throw new Error('simulated proxy set failure');
          }
          currentValue = details.value;
          setCalls.push({ value: details.value, scope: details.scope });
          callback();
        },
      },
    },
    storage: {
      local: {
        get: (keys: string[] | string, callback: (items: Record<string, unknown>) => void) => {
          const list = Array.isArray(keys) ? keys : [keys];
          const result: Record<string, unknown> = {};
          list.forEach(key => { if (Object.prototype.hasOwnProperty.call(storage, key)) result[key] = storage[key]; });
          callback(result);
        },
        set: (items: Record<string, unknown>, callback: () => void) => { Object.assign(storage, items); callback(); },
        remove: (keys: string[] | string, callback: () => void) => {
          const list = Array.isArray(keys) ? keys : [keys];
          list.forEach(key => delete storage[key]);
          callback();
        },
      },
    },
    runtime: { lastError: null, onMessage: { addListener: () => undefined } },
    alarms: { create: () => undefined, clear: () => undefined, onAlarm: { addListener: () => undefined } },
    management: { uninstallSelf: (_opts: unknown, callback: () => void) => callback() },
    webRequest: undefined,
  };

  return {
    chrome,
    storage,
    setCalls,
    getCurrentValue: () => currentValue,
    failNextSets: (count: number) => { failFirstSets = count; },
  };
}

function loadExtension(config = runtimeConfig(), fetchResponse: unknown = { revoked: false, expiresAt: Date.now() + 600000 }) {
  const mock = createChrome({ mode: 'system' });
  const fetchCalls: FetchCall[] = [];
  const sandbox: Record<string, any> = {
    chrome: mock.chrome,
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    AbortController,
    Blob,
    URL,
    TextEncoder,
    TextDecoder,
    module: { exports: {} },
    __REDPROXY_TEST__: true,
    fetch: async (url: string, init: { headers?: Record<string, string>; body?: string } = {}) => {
      fetchCalls.push({ url, headers: init.headers ?? {}, body: init.body });
      const payload = typeof fetchResponse === 'function' ? (fetchResponse as (url: string, init: unknown) => unknown)(url, init) : fetchResponse;
      return { ok: true, status: 200, json: async () => payload, text: async () => JSON.stringify(payload) };
    },
  };
  const context = vm.createContext(sandbox);
  const code = renderBackground(config, path.resolve(__dirname, '../extension-template'));
  new vm.Script(code, { filename: 'background.js' }).runInContext(context);
  const api = sandbox.RedProxy as Record<string, any>;
  if (!api) throw new Error('RedProxy API was not exported by the extension template');
  return { api, mock, fetchCalls, config };
}

describe('extension proxy behaviour', () => {
  it('builds the temporary proxy configuration for socks4 and socks5', () => {
    const { api } = loadExtension();
    const socks5 = api.buildProxyConfig({ scheme: 'socks5', host: '127.0.0.1', port: 10809 });
    expect(socks5).toMatchObject({
      mode: 'fixed_servers',
      rules: { singleProxy: { scheme: 'socks5', host: '127.0.0.1', port: 10809 }, bypassList: ['<local>'] },
    });
    const socks4 = api.buildProxyConfig({ scheme: 'socks4', host: '10.0.0.2', port: 1080 });
    expect(socks4.rules.singleProxy.scheme).toBe('socks4');
  });

  it('saves the original proxy and applies the temporary node', async () => {
    const original = { mode: 'system' };
    const { api, mock } = loadExtensionWithOriginal(original);
    await api.saveOriginalProxy();
    await api.applyProxy();
    expect(mock.storage['redproxy_original_proxy']).toMatchObject({ value: original, scope: 'regular' });
    expect(mock.getCurrentValue()).toMatchObject({
      mode: 'fixed_servers',
      rules: { singleProxy: { scheme: 'socks5', host: '127.0.0.1', port: 10809 } },
    });
  });

  it('restores the original proxy settings and retries failures', async () => {
    const original = { mode: 'system' };
    const { api, mock } = loadExtensionWithOriginal(original);
    await api.saveOriginalProxy();
    await api.applyProxy();
    mock.failNextSets(2);
    await api.restoreOriginalProxy();
    expect(mock.getCurrentValue()).toEqual(original);
    expect(mock.storage['redproxy_temp_applied']).toBe(false);
  });

  it('rotates the single-use enrollment token and persists the access token', async () => {
    const rotated = 'rotated-access-token';
    const { api, mock, fetchCalls } = loadExtension(runtimeConfig(), { revoked: false, expiresAt: Date.now() + 600000, token: rotated });
    await api.saveOriginalProxy();
    await api.applyProxy();
    const result = await api.heartbeat();
    expect(result.ok).toBe(true);
    expect(mock.storage['redproxy_access_token']).toBe(rotated);
    expect(fetchCalls.length).toBe(1);
    expect(fetchCalls[0]?.headers.Authorization).toBe('Bearer initial-enrollment-token');
    // A later heartbeat uses the rotated token, never the artifact token again.
    await api.heartbeat();
    expect(fetchCalls[1]?.headers.Authorization).toBe(`Bearer ${rotated}`);
  });

  it('cleans up idempotently and restores the original proxy', async () => {
    const original = { mode: 'system' };
    const { api, mock } = loadExtensionWithOriginal(original);
    await api.start();
    await api.cleanup('test');
    await api.cleanup('test-again');
    expect(mock.getCurrentValue()).toEqual(original);
    expect(mock.storage['redproxy_original_proxy']).toBeUndefined();
    expect(mock.storage['redproxy_access_token']).toBeUndefined();
  });
});

function loadExtensionWithOriginal(original: unknown) {
  const mock = createChrome(original);
  const sandbox: Record<string, any> = {
    chrome: mock.chrome,
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    AbortController,
    Blob,
    URL,
    TextEncoder,
    TextDecoder,
    module: { exports: {} },
    __REDPROXY_TEST__: true,
    fetch: async () => ({ ok: true, status: 200, json: async () => ({ revoked: false }), text: async () => '{}' }),
  };
  const context = vm.createContext(sandbox);
  const code = renderBackground(runtimeConfig(), path.resolve(__dirname, '../extension-template'));
  new vm.Script(code, { filename: 'background.js' }).runInContext(context);
  return { api: sandbox.RedProxy as Record<string, any>, mock };
}
