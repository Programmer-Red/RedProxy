import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crx3 from 'crx3';
import type { AppConfig, ExtensionRuntimeConfig, NodeRecord } from './types';

export interface ExtensionArtifacts {
  crx: Buffer;
  zip: Buffer;
  appId?: string;
}

export interface BuildArtifactsOptions {
  runtimeConfig: ExtensionRuntimeConfig;
  keyPath: string;
  crxKeyBits: number;
  templateDir?: string;
}

export function extensionTemplateDir(): string {
  return process.env.REDPROXY_EXTENSION_TEMPLATE_DIR || path.resolve(process.cwd(), 'extension-template');
}

export function sanitizeFileToken(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 80) || 'session';
}

export function buildManifest(runtimeConfig: ExtensionRuntimeConfig): Record<string, unknown> {
  const permissions = ['proxy', 'storage', 'alarms'];
  const hostPermissions: string[] = [];
  if (runtimeConfig.node.username || runtimeConfig.node.password) {
    permissions.push('webRequest', 'webRequestAuthProvider');
    hostPermissions.push('<all_urls>');
  }

  const manifest: Record<string, unknown> = {
    manifest_version: 3,
    name: 'RedProxy Temporary Proxy',
    description: 'Temporarily applies a RedProxy node and self-uninstalls when the one-time session ends.',
    version: '0.1.0',
    permissions,
    background: {
      service_worker: 'background.js',
    },
    action: {
      default_title: 'RedProxy Temporary Proxy',
    },
  };

  if (hostPermissions.length > 0) {
    manifest.host_permissions = hostPermissions;
  }
  return manifest;
}

export function renderBackground(runtimeConfig: ExtensionRuntimeConfig, templateDir = extensionTemplateDir()): string {
  const templatePath = path.join(templateDir, 'background.js');
  const template = fs.readFileSync(templatePath, 'utf8');
  const json = JSON.stringify(runtimeConfig).replace(/</g, '\\u003c');
  const rendered = template.replace(/__REDPROXY_CONFIG__/g, json);
  if (rendered === template) {
    throw new Error(`Extension template did not contain __REDPROXY_CONFIG__ placeholder: ${templatePath}`);
  }
  return rendered;
}

async function makeTempDir(prefix: string): Promise<string> {
  return fs.promises.mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function ensureCrxPrivateKey(keyPath: string, bits: number): Promise<void> {
  if (fs.existsSync(keyPath)) {
    return;
  }
  await fs.promises.mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  await fs.promises.writeFile(keyPath, privateKey, { mode: 0o600 });
}

export async function buildExtensionArtifacts(options: BuildArtifactsOptions): Promise<ExtensionArtifacts> {
  const templateDir = options.templateDir || extensionTemplateDir();
  const manifest = buildManifest(options.runtimeConfig);
  const background = renderBackground(options.runtimeConfig, templateDir);

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
    await crx3([manifestPath, backgroundPath], {
      keyPath: options.keyPath,
      crxPath,
      zipPath,
    });

    const [crx, zip] = await Promise.all([fs.promises.readFile(crxPath), fs.promises.readFile(zipPath)]);
    return { crx, zip };
  } finally {
    await Promise.allSettled([
      fs.promises.rm(extDir, { recursive: true, force: true }),
      fs.promises.rm(outDir, { recursive: true, force: true }),
    ]);
  }
}

export function buildRuntimeConfig(
  config: AppConfig,
  session: { id: string; deviceId: string; expiresAt: number },
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
    idleSeconds: config.sessionIdleSeconds,
    node: {
      id: node.id,
      name: node.name,
      scheme: node.scheme,
      host: node.host,
      port: node.port,
      username: node.username,
      password: node.password,
    },
  };
}
