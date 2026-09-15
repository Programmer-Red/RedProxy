import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crx3 from 'crx3';
import { readAsset } from './assets';
import type { AppConfig, ExtensionNodeConfig, ExtensionRuntimeConfig, NodeRecord, ProxyScheme } from './types';

export interface ExtensionArtifacts {
  crx: Buffer;
  zip: Buffer;
  appId?: string;
}

export interface BuildArtifactsOptions {
  runtimeConfig: ExtensionRuntimeConfig;
  keyPath: string;
  crxKeyBits: number;
  templateDir?: string | null;
}

export function defaultExtensionTemplateDir(): string {
  return path.resolve(process.cwd(), 'extension-template');
}

export function sanitizeFileToken(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 80) || 'session';
}

export function buildManifest(runtimeConfig: ExtensionRuntimeConfig): Record<string, unknown> {
  const permissions = ['proxy', 'storage', 'alarms', 'management'];
  const hostPermissions: string[] = [];
  if (runtimeConfig.node.username || runtimeConfig.node.password) {
    permissions.push('webRequest', 'webRequestAuthProvider');
    hostPermissions.push('<all_urls>');
  }

  const manifest: Record<string, unknown> = {
    manifest_version: 3,
    name: 'RedProxy Temporary Proxy',
    description: 'Temporarily applies a RedProxy node and self-uninstalls when the one-time session ends.',
    version: '0.2.0',
    minimum_chrome_version: '96',
    permissions,
    background: { service_worker: 'background.js' },
    action: { default_title: 'RedProxy Temporary Proxy' },
  };

  if (hostPermissions.length > 0) manifest.host_permissions = hostPermissions;
  return manifest;
}

export function renderBackground(runtimeConfig: ExtensionRuntimeConfig, templateDir?: string | null): string {
  const diskTemplate = templateDir ? path.join(templateDir, 'background.js') : null;
  let template: string | null = null;
  if (diskTemplate && fs.existsSync(diskTemplate)) {
    template = fs.readFileSync(diskTemplate, 'utf8');
  }
  template = template ?? readAsset('extension-template/background.js', null);
  if (!template) {
    throw new Error(`Extension background template not found (looked in ${diskTemplate ?? 'embedded assets'})`);
  }
  const json = JSON.stringify(runtimeConfig).replace(/</g, '\\u003c');
  const rendered = template.replace(/__REDPROXY_CONFIG__/g, json);
  if (rendered === template) {
    throw new Error('Extension template did not contain __REDPROXY_CONFIG__ placeholder');
  }
  return rendered;
}

async function makeTempDir(prefix: string): Promise<string> {
  return fs.promises.mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function ensureCrxPrivateKey(keyPath: string, bits: number): Promise<void> {
  if (fs.existsSync(keyPath)) return;
  await fs.promises.mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  await fs.promises.writeFile(keyPath, privateKey, { mode: 0o600 });
}

export async function buildExtensionArtifacts(options: BuildArtifactsOptions): Promise<ExtensionArtifacts> {
  const manifest = buildManifest(options.runtimeConfig);
  const background = renderBackground(options.runtimeConfig, options.templateDir);

  const extDir = await makeTempDir('redproxy-extension-src-');
  const outDir = await makeTempDir('redproxy-extension-out-');
  try {
    const manifestPath = path.join(extDir, 'manifest.json');
    const backgroundPath = path.join(extDir, 'background.js');
    await fs.promises.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
    await fs.promises.writeFile(backgroundPath, background, 'utf8');

    await ensureCrxPrivateKey(options.keyPath, options.crxKeyBits);

    const crxPath = path.join(outDir, 'extension.crx');
    const zipPath = path.join(outDir, 'extension.zip');
    await crx3([manifestPath, backgroundPath], { keyPath: options.keyPath, crxPath, zipPath });

    const [crx, zip] = await Promise.all([fs.promises.readFile(crxPath), fs.promises.readFile(zipPath)]);
    return { crx, zip };
  } finally {
    await Promise.allSettled([
      fs.promises.rm(extDir, { recursive: true, force: true }),
      fs.promises.rm(outDir, { recursive: true, force: true }),
    ]);
  }
}

export function extensionNodeConfig(node: NodeRecord): ExtensionNodeConfig {
  if (node.kind === 'xray') {
    const scheme: ProxyScheme =
      node.localScheme === 'http' || node.localScheme === 'https' || node.localScheme === 'socks4' || node.localScheme === 'socks5'
        ? node.localScheme
        : 'socks5';
    return {
      id: node.id,
      name: node.name,
      scheme,
      host: node.localHost || '127.0.0.1',
      port: node.localPort || 10808,
      username: null,
      password: null,
    };
  }
  return {
    id: node.id,
    name: node.name,
    scheme: node.scheme,
    host: node.host,
    port: node.port,
    username: node.username,
    password: node.password,
  };
}

export function buildRuntimeConfig(
  config: AppConfig,
  session: { id: string; deviceId: string; expiresAt: number; enrollmentTokenExpiresAt?: number | null },
  node: NodeRecord,
  extensionToken: string,
  now: number,
): ExtensionRuntimeConfig {
  return {
    serverUrl: config.publicBaseUrl,
    extensionToken,
    sessionId: session.id,
    deviceId: session.deviceId,
    expiresAt: session.expiresAt,
    generatedAt: now,
    heartbeatIntervalSeconds: 15,
    enrollmentExpiresAt: session.enrollmentTokenExpiresAt ?? now + config.enrollmentTtlSeconds * 1000,
    idleSeconds: config.sessionIdleSeconds,
    node: extensionNodeConfig(node),
  };
}
