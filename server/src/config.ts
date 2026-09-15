import fs from 'node:fs';
import path from 'node:path';
import type { AppConfig } from './types';

function intFromEnv(value: string | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || value.trim() === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    throw new Error(`Invalid integer value "${value}" (expected ${min}..${max})`);
  }
  return parsed;
}

function boolFromEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  throw new Error(`Invalid boolean value "${value}"`);
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const port = intFromEnv(env.PORT, 3000, 1, 65535);
  const dataDir = path.resolve(env.DATA_DIR || './data');
  const keyCandidate = env.CRX_PRIVATE_KEY_PATH || path.join(dataDir, 'redproxy.pem');
  const crxPrivateKeyPath = path.isAbsolute(keyCandidate) ? keyCandidate : path.resolve(keyCandidate);
  const nodeEnv = env.NODE_ENV || 'development';
  const cookieSecureDefault = nodeEnv === 'production';

  return {
    nodeEnv,
    port,
    publicBaseUrl: (env.PUBLIC_BASE_URL || `http://localhost:${port}`).replace(/\/+$/, ''),
    dataDir,
    crxPrivateKeyPath,
    sessionTtlSeconds: intFromEnv(env.SESSION_TTL_SECONDS, 3600, 60, 86400),
    sessionIdleSeconds: intFromEnv(env.SESSION_IDLE_SECONDS, 90, 15, 3600),
    maxConcurrentDevices: intFromEnv(env.MAX_CONCURRENT_DEVICES, 2, 1, 1000),
    cookieSecure: boolFromEnv(env.COOKIE_SECURE, cookieSecureDefault),
    authSessionTtlSeconds: intFromEnv(env.AUTH_SESSION_TTL_SECONDS, 12 * 3600, 300, 30 * 86400),
    loginMaxAttempts: intFromEnv(env.LOGIN_MAX_ATTEMPTS, 5, 1, 1000),
    loginWindowSeconds: intFromEnv(env.LOGIN_WINDOW_SECONDS, 300, 10, 86400),
    crxKeyBits: intFromEnv(env.CRX_KEY_BITS, 2048, 2048, 4096),
    trustProxy: boolFromEnv(env.TRUST_PROXY, false),
    allowInsecureHttp: boolFromEnv(env.ALLOW_INSECURE_HTTP, false),
    adminTotpSecret: env.ADMIN_TOTP_SECRET?.trim() || null,
  };
}

export function ensureDataDir(config: AppConfig): void {
  fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
}

export function toTestConfig(overrides: Partial<AppConfig> & { dataDir: string }): AppConfig {
  return {
    nodeEnv: 'test',
    port: 0,
    publicBaseUrl: 'http://127.0.0.1:3000',
    crxPrivateKeyPath: path.join(overrides.dataDir, 'redproxy.pem'),
    sessionTtlSeconds: 600,
    sessionIdleSeconds: 90,
    maxConcurrentDevices: 2,
    cookieSecure: false,
    authSessionTtlSeconds: 3600,
    loginMaxAttempts: 5,
    loginWindowSeconds: 300,
    crxKeyBits: 2048,
    trustProxy: false,
    allowInsecureHttp: true,
    adminTotpSecret: null,
    ...overrides,
  };
}
