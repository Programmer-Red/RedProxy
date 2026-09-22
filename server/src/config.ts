import fs from 'node:fs';
import path from 'node:path';
import type { AppConfig, AuthMode } from './types';

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

function proxyModeFromEnv(value: string | undefined): 'server' | 'direct' {
  if (value === undefined || value.trim() === '') return 'server';
  const normalized = value.trim().toLowerCase();
  if (normalized === 'server' || normalized === 'direct') return normalized;
  throw new Error(`Invalid PROXY_MODE "${value}" (expected server or direct)`);
}

function authModeFromEnv(value: string | undefined, fallback: AuthMode): AuthMode {
  if (value === undefined || value.trim() === '') return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'password' || normalized === 'totp' || normalized === 'totp_password') return normalized;
  throw new Error(`Invalid auth mode "${value}" (expected password, totp or totp_password)`);
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
    host: env.HOST || '0.0.0.0',
    port,
    adminEnabled: boolFromEnv(env.ADMIN_ENABLED, true),
    adminHost: env.ADMIN_HOST || '127.0.0.1',
    adminPort: intFromEnv(env.ADMIN_PORT, port + 1, 1, 65535),
    publicBaseUrl: (env.PUBLIC_BASE_URL || `http://localhost:${port}`).replace(/\/+$/, ''),
    dataDir,
    crxPrivateKeyPath,
    sessionTtlSeconds: intFromEnv(env.SESSION_TTL_SECONDS, 3600, 60, 7 * 86400),
    sessionIdleSeconds: intFromEnv(env.SESSION_IDLE_SECONDS, 90, 15, 3600),
    enrollmentTtlSeconds: intFromEnv(env.ENROLLMENT_TTL_SECONDS, 120, 30, 3600),
    tokenGraceSeconds: intFromEnv(env.TOKEN_GRACE_SECONDS, 30, 0, 600),
    maxConcurrentDevices: intFromEnv(env.MAX_CONCURRENT_DEVICES, 2, 1, 1000),
    cookieSecure: boolFromEnv(env.COOKIE_SECURE, cookieSecureDefault),
    authSessionTtlSeconds: intFromEnv(env.AUTH_SESSION_TTL_SECONDS, 12 * 3600, 300, 30 * 86400),
    loginMaxAttempts: intFromEnv(env.LOGIN_MAX_ATTEMPTS, 5, 1, 1000),
    loginWindowSeconds: intFromEnv(env.LOGIN_WINDOW_SECONDS, 300, 10, 86400),
    loginBanSeconds: intFromEnv(env.LOGIN_BAN_SECONDS, 900, 0, 7 * 86400),
    crxKeyBits: intFromEnv(env.CRX_KEY_BITS, 2048, 2048, 4096),
    trustProxy: boolFromEnv(env.TRUST_PROXY, false),
    allowInsecureHttp: boolFromEnv(env.ALLOW_INSECURE_HTTP, false),
    adminTotpSecret: env.ADMIN_TOTP_SECRET?.trim() || null,
    adminAuthMode: authModeFromEnv(env.AUTH_MODE, 'password'),
    userAuthMode: authModeFromEnv(env.USER_AUTH_MODE, 'totp'),
    adminUsername: (env.ADMIN_USERNAME || 'admin').trim() || 'admin',
    adminPassword: env.ADMIN_PASSWORD || 'redproxy',
    proxyMode: proxyModeFromEnv(env.PROXY_MODE),
    proxyConnectTimeoutMs: intFromEnv(env.PROXY_CONNECT_TIMEOUT_MS, 10000, 1000, 120000),
    proxyEnabled: boolFromEnv(env.PROXY_ENABLED, true),
    tlsEnabled: boolFromEnv(env.TLS_ENABLED, false),
    tlsCertPath: env.TLS_CERT_PATH ? path.resolve(env.TLS_CERT_PATH) : null,
    tlsKeyPath: env.TLS_KEY_PATH ? path.resolve(env.TLS_KEY_PATH) : null,
    staticDir: env.STATIC_DIR ? path.resolve(env.STATIC_DIR) : null,
    templateDir: env.EXTENSION_TEMPLATE_DIR ? path.resolve(env.EXTENSION_TEMPLATE_DIR) : null,
  };
}

export function ensureDataDir(config: AppConfig): void {
  fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
}

export function toTestConfig(overrides: Partial<AppConfig> & { dataDir: string }): AppConfig {
  return {
    nodeEnv: 'test',
    host: '127.0.0.1',
    port: 0,
    adminEnabled: true,
    adminHost: '127.0.0.1',
    adminPort: 0,
    publicBaseUrl: 'http://127.0.0.1:3000',
    crxPrivateKeyPath: path.join(overrides.dataDir, 'redproxy.pem'),
    sessionTtlSeconds: 600,
    sessionIdleSeconds: 90,
    enrollmentTtlSeconds: 120,
    tokenGraceSeconds: 30,
    maxConcurrentDevices: 2,
    cookieSecure: false,
    authSessionTtlSeconds: 3600,
    loginMaxAttempts: 5,
    loginWindowSeconds: 300,
    loginBanSeconds: 300,
    crxKeyBits: 2048,
    trustProxy: false,
    allowInsecureHttp: true,
    adminTotpSecret: null,
    adminAuthMode: 'password',
    userAuthMode: 'totp',
    adminUsername: 'admin',
    adminPassword: 'redproxy',
    proxyMode: 'server',
    proxyConnectTimeoutMs: 10000,
    proxyEnabled: true,
    tlsEnabled: false,
    tlsCertPath: null,
    tlsKeyPath: null,
    staticDir: null,
    templateDir: null,
    ...overrides,
  };
}
