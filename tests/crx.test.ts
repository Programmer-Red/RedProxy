import fs from 'node:fs';
import path from 'node:path';
import JSZip from 'jszip';
import { afterEach, describe, expect, it } from 'vitest';
import { buildExtensionArtifacts, buildRuntimeConfig } from '../server/src/extension';
import { toTestConfig } from '../server/src/config';
import type { ExtensionRuntimeConfig, NodeRecord } from '../server/src/types';
import { tmpDir } from './helpers';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

function node(): NodeRecord {
  return {
    id: 'tokyo-1',
    name: 'Tokyo',
    scheme: 'http',
    host: '127.0.0.1',
    port: 10809,
    username: null,
    password: null,
    enabled: true,
    createdAt: Date.now(),
  };
}

describe('dynamic CRX3 generation', () => {
  it('builds a CRX3 and ZIP containing manifest.json and background.js', async () => {
    const dataDir = tmpDir();
    tempDirs.push(dataDir);
    const config = toTestConfig({ dataDir, crxKeyBits: 2048 });
    const runtime: ExtensionRuntimeConfig = buildRuntimeConfig(
      config,
      { id: '11111111-2222-3333-4444-555555555555', deviceId: 'device-test-1', expiresAt: Date.now() + 600000 },
      node(),
      'one-time-token-abcdef',
      Date.now(),
    );

    const artifacts = await buildExtensionArtifacts({
      runtimeConfig: runtime,
      keyPath: config.crxPrivateKeyPath,
      crxKeyBits: config.crxKeyBits,
      templateDir: path.resolve(__dirname, '../extension-template'),
    });

    expect(artifacts.crx.length).toBeGreaterThan(1000);
    expect(artifacts.crx.subarray(0, 4).toString('utf8')).toBe('Cr24');
    expect(artifacts.crx.readUInt32LE(4)).toBe(3);
    expect(fs.existsSync(config.crxPrivateKeyPath)).toBe(true);

    // A CRX3 file is: "Cr24" + version + header length + signed header + ZIP.
    const headerLength = artifacts.crx.readUInt32LE(8);
    const embeddedZip = artifacts.crx.subarray(12 + headerLength);
    expect(embeddedZip.subarray(0, 2).toString('utf8')).toBe('PK');
    const crxZip = await JSZip.loadAsync(embeddedZip);
    expect(crxZip.file('manifest.json')).not.toBeNull();
    expect(crxZip.file('background.js')).not.toBeNull();

    const zip = await JSZip.loadAsync(artifacts.zip);
    expect(zip.file('manifest.json')).not.toBeNull();
    expect(zip.file('background.js')).not.toBeNull();

    const manifest = JSON.parse(await zip.file('manifest.json')!.async('string'));
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions).toContain('proxy');
    expect(manifest.permissions).toContain('storage');
    expect(manifest.permissions).toContain('alarms');
    expect(manifest.background.service_worker).toBe('background.js');

    const background = await zip.file('background.js')!.async('string');
    expect(background).toContain('one-time-token-abcdef');
    expect(background).toContain('127.0.0.1');
    expect(background).toContain('10809');
    expect(background).not.toContain('__REDPROXY_CONFIG__');
  });
});
