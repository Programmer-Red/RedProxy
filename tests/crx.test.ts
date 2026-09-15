import fs from 'node:fs';
import path from 'node:path';
import JSZip from 'jszip';
import { afterEach, describe, expect, it } from 'vitest';
import { buildExtensionArtifacts, buildRuntimeConfig, extensionNodeConfig } from '../server/src/extension';
import { toTestConfig } from '../server/src/config';
import type { ExtensionRuntimeConfig } from '../server/src/types';
import { sampleNode, tmpDir } from './helpers';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

function sessionStub() {
  return { id: '11111111-2222-3333-4444-555555555555', deviceId: 'device-test-1', expiresAt: Date.now() + 600000, enrollmentTokenExpiresAt: Date.now() + 120000 };
}

async function build(node: Parameters<typeof extensionNodeConfig>[0], token = 'one-time-token-abcdef') {
  const dataDir = tmpDir();
  tempDirs.push(dataDir);
  const config = toTestConfig({ dataDir, crxKeyBits: 2048 });
  const runtime: ExtensionRuntimeConfig = buildRuntimeConfig(config, sessionStub(), node, token, Date.now());
  const artifacts = await buildExtensionArtifacts({
    runtimeConfig: runtime,
    keyPath: config.crxPrivateKeyPath,
    crxKeyBits: config.crxKeyBits,
    templateDir: path.resolve(__dirname, '../extension-template'),
  });
  return { artifacts, config, runtime };
}

describe('dynamic CRX3 generation', () => {
  it('builds a CRX3 and ZIP containing manifest.json and background.js', async () => {
    const { artifacts, config } = await build(sampleNode({ scheme: 'socks4', host: '10.0.0.5', port: 10808 }));
    expect(artifacts.crx.length).toBeGreaterThan(1000);
    expect(artifacts.crx.subarray(0, 4).toString('utf8')).toBe('Cr24');
    expect(artifacts.crx.readUInt32LE(4)).toBe(3);
    expect(fs.existsSync(config.crxPrivateKeyPath)).toBe(true);

    const headerLength = artifacts.crx.readUInt32LE(8);
    const embeddedZip = artifacts.crx.subarray(12 + headerLength);
    expect(embeddedZip.subarray(0, 2).toString('utf8')).toBe('PK');
    const crxZip = await JSZip.loadAsync(embeddedZip);
    expect(crxZip.file('manifest.json')).not.toBeNull();
    expect(crxZip.file('background.js')).not.toBeNull();

    const zip = await JSZip.loadAsync(artifacts.zip);
    const manifest = JSON.parse(await zip.file('manifest.json')!.async('string'));
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions).toEqual(expect.arrayContaining(['proxy', 'storage', 'alarms', 'management']));
    expect(manifest.background.service_worker).toBe('background.js');

    const background = await zip.file('background.js')!.async('string');
    expect(background).toContain('one-time-token-abcdef');
    expect(background).toContain('socks4');
    expect(background).toContain('10.0.0.5');
    expect(background).toContain('10808');
    expect(background).toContain('enrollmentExpiresAt');
    expect(background).not.toContain('__REDPROXY_CONFIG__');
  });

  it('maps an Xray node to its local HTTP/SOCKS inbound for the extension', async () => {
    const xrayNode = sampleNode({
      kind: 'xray',
      scheme: 'socks5',
      host: 'remote.example.com',
      port: 443,
      xray: { protocol: 'vless', uuid: '11111111-1111-1111-1111-111111111111', network: 'ws', security: 'tls', sni: 'remote.example.com', path: '/ws' },
      localScheme: 'http',
      localHost: '127.0.0.1',
      localPort: 18080,
    });
    const { artifacts } = await build(xrayNode, 'xray-one-time-token');
    const zip = await JSZip.loadAsync(artifacts.zip);
    const background = await zip.file('background.js')!.async('string');
    expect(background).toContain('xray-one-time-token');
    expect(background).toContain('127.0.0.1');
    expect(background).toContain('18080');
    expect(background).toContain('"scheme":"http"');
    // The extension must never be handed the remote Xray endpoint directly.
    expect(background).not.toContain('remote.example.com');
  });
});
