import path from 'node:path';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';
import { renderBackground } from '../server/src/extension';
import type { ExtensionRuntimeConfig } from '../server/src/types';

interface MockChrome {
  proxy: {
    settings: {
      get: (details: unknown, callback: (value: unknown) => void) => void;
      set: (details: { value: unknown; scope?: string }, callback: () => void) => void;
    };
  };
  storage: { local: Record<string, unknown>; get: unknown; set: unknown; remove: unknown };
  runtime: { lastError: null; onMessage: { addListener: () => void } };
  alarms: { create: () => void; clear: () => void; onAlarm: { addListener: () => void } };
  management: { uninstallSelf: (opts: unknown, callback: () => void) => void };
}

function createChrome(originalValue: unknown) {
  const storage: Record<string, unknown> = {};
  const setCalls: Array<{ value: unknown; scope?: string }> = [];
  let currentValue = originalValue;
  let failFirstSets = 0;

  const chrome: MockChrome = {
    proxy: {
      settings: {
        get: (_details, callback) => callback({ value: currentValue, levelOfControl: 'controllable_by_this_extension' }),
        set: (details, callback) => {
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
          const keyList = Array.isArray(keys) ? keys : [keys];
          const result: Record<string, unknown> = {};
          keyList.forEach(key => {
            if (Object.prototype.hasOwnProperty.call(storage, key)) result[key] = storage[key];
          });
          callback(result);
        },
        set: (items: Record<string, unknown>, callback: () => void) => {
          Object.assign(storage, items);
          callback();
        },
        remove: (keys: string[] | string, callback: () => void) => {
          const keyList = Array.isArray(keys) ? keys : [keys];
          keyList.forEach(key => delete storage[key]);
          callback();
        },
      } as unknown as MockChrome['storage']['local'],
      get: undefined,
      set: undefined,
      remove: undefined,
    },
    runtime: { lastError: null, onMessage: { addListener: () => undefined } },
    alarms: { create: () => undefined, clear: () => undefined, onAlarm: { addListener: () => undefined } },
    management: { uninstallSelf: (_opts, callback) => callback() },
  };

  return {
    chrome,
    storage,
    setCalls,
    getCurrentValue: () => currentValue,
    failNextSets: (count: number) => { failFirstSets = count; },
  };
}

function runtimeConfig(): ExtensionRuntimeConfig {
  return {
    serverUrl: 'https://redproxy.example.com',
    extensionToken: 'test-extension-token',
    sessionId: 'session-1',
    deviceId: 'device-1',
    expiresAt: Date.now() + 600000,
    generatedAt: Date.now(),
    heartbeatIntervalSeconds: 15,
    idleSeconds: 90,
    node: { id: 'tokyo-1', name: 'Tokyo', scheme: 'socks5', host: '127.0.0.1', port: 10809, username: null, password: null },
  };
}

function loadExtension(originalValue: unknown) {
  const mock = createChrome(originalValue);
  const sandbox: Record<string, unknown> = {
    chrome: mock.chrome,
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    fetch: async () => ({ ok: true, status: 200, json: async () => ({ revoked: false, expiresAt: Date.now() + 600000 }) }),
    AbortController,
    Blob,
    URL,
    TextEncoder,
    TextDecoder,
    module: { exports: {} },
  };
  sandbox.__REDPROXY_TEST__ = true;
  const context = vm.createContext(sandbox);
  const code = renderBackground(runtimeConfig(), path.resolve(__dirname, '../extension-template'));
  new vm.Script(code, { filename: 'background.js' }).runInContext(context);
  const api = (sandbox as { RedProxy?: Record<string, any> }).RedProxy;
  if (!api) throw new Error('RedProxy API was not exported by the extension template');
  return { api, mock };
}

describe('extension proxy restore logic', () => {
  it('saves the original proxy and builds the temporary node configuration', async () => {
    const original = { mode: 'system' };
    const { api, mock } = loadExtension(original);
    await api.saveOriginalProxy();
    await api.applyProxy();

    expect(mock.storage['redproxy_original_proxy']).toMatchObject({ value: original, scope: 'regular' });
    expect(mock.getCurrentValue()).toMatchObject({
      mode: 'fixed_servers',
      rules: {
        singleProxy: { scheme: 'socks5', host: '127.0.0.1', port: 10809 },
        bypassList: ['<local>'],
      },
    });
  });

  it('restores the saved original proxy settings', async () => {
    const original = { mode: 'system' };
    const { api, mock } = loadExtension(original);
    await api.saveOriginalProxy();
    await api.applyProxy();
    await api.restoreOriginalProxy();

    expect(mock.getCurrentValue()).toEqual(original);
    expect(mock.storage['redproxy_temp_applied']).toBe(false);
  });

  it('retries restoring the original proxy settings', async () => {
    const original = { mode: 'system' };
    const { api, mock } = loadExtension(original);
    await api.saveOriginalProxy();
    await api.applyProxy();
    mock.failNextSets(2);
    await api.restoreOriginalProxy();
    expect(mock.getCurrentValue()).toEqual(original);
  });

  it('cleans up idempotently and restores the original proxy', async () => {
    const original = { mode: 'system' };
    const { api, mock } = loadExtension(original);
    await api.start();
    await api.cleanup('test');
    await api.cleanup('test-again');
    expect(mock.getCurrentValue()).toEqual(original);
    expect(mock.storage['redproxy_original_proxy']).toBeUndefined();
  });
});
