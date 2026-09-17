import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { createApp } from './app';
import { ensureDataDir, loadConfig } from './config';
import { ensureCrxPrivateKey } from './extension';
import { SettingsService, buildOtpAuthUri, randomBase32Secret } from './settings';
import type { AppConfig } from './types';

const VERSION = '0.2.0';

interface ParsedArgs {
  command: string;
  flags: Record<string, string | boolean>;
  positionals: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags: Record<string, string | boolean> = {};
  const positionals: string[] = [];
  let command = 'serve';
  let commandSet = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (arg.startsWith('--')) {
      let key = arg.slice(2);
      let value: string | boolean = true;
      const eq = key.indexOf('=');
      if (eq >= 0) {
        value = key.slice(eq + 1);
        key = key.slice(0, eq);
      } else if (i + 1 < argv.length && argv[i + 1] !== undefined && !argv[i + 1]!.startsWith('--')) {
        value = argv[i + 1]!;
        i += 1;
      }
      flags[key] = value;
      continue;
    }
    if (arg.startsWith('-') && arg.length > 1) {
      const short = arg.slice(1);
      if (short === 'h') flags.help = true;
      else if (short === 'v') flags.version = true;
      else flags[short] = true;
      continue;
    }
    if (!commandSet) {
      command = arg;
      commandSet = true;
    } else {
      positionals.push(arg);
    }
  }
  return { command, flags, positionals };
}

function flagString(flags: Record<string, string | boolean>, name: string): string | undefined {
  const value = flags[name];
  return typeof value === 'string' ? value : undefined;
}

function flagBool(flags: Record<string, string | boolean>, name: string): boolean | undefined {
  const value = flags[name];
  if (value === undefined) return undefined;
  if (typeof value === 'boolean') return value;
  const normalized = value.toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return undefined;
}

function applyServeEnv(flags: Record<string, string | boolean>): void {
  const mapping: Array<[string, string]> = [
    ['host', 'HOST'],
    ['port', 'PORT'],
    ['data-dir', 'DATA_DIR'],
    ['public-url', 'PUBLIC_BASE_URL'],
    ['session-ttl', 'SESSION_TTL_SECONDS'],
    ['idle', 'SESSION_IDLE_SECONDS'],
    ['max-devices', 'MAX_CONCURRENT_DEVICES'],
    ['auth-mode', 'AUTH_MODE'],
    ['user-auth-mode', 'USER_AUTH_MODE'],
    ['crx-key-bits', 'CRX_KEY_BITS'],
    ['login-max-attempts', 'LOGIN_MAX_ATTEMPTS'],
    ['login-ban-seconds', 'LOGIN_BAN_SECONDS'],
    ['static-dir', 'STATIC_DIR'],
    ['template-dir', 'EXTENSION_TEMPLATE_DIR'],
    ['enrollment-ttl', 'ENROLLMENT_TTL_SECONDS'],
    ['admin-host', 'ADMIN_HOST'],
    ['admin-port', 'ADMIN_PORT'],
  ];
  for (const [flag, env] of mapping) {
    const value = flagString(flags, flag);
    if (value !== undefined) process.env[env] = value;
  }
  const booleanMapping: Array<[string, string]> = [
    ['cookie-secure', 'COOKIE_SECURE'],
    ['allow-insecure-http', 'ALLOW_INSECURE_HTTP'],
    ['trust-proxy', 'TRUST_PROXY'],
    ['admin-enabled', 'ADMIN_ENABLED'],
  ];
  for (const [flag, env] of booleanMapping) {
    const value = flagBool(flags, flag);
    if (value !== undefined) process.env[env] = value ? 'true' : 'false';
  }
  if (flagBool(flags, 'no-cookie-secure')) process.env.COOKIE_SECURE = 'false';
  if (flagBool(flags, 'no-admin')) process.env.ADMIN_ENABLED = 'false';
}

export function helpText(): string {
  return `RedProxy ${VERSION} - TOTP-gated one-time CRX3 browser proxy

Usage:
  redproxy [serve] [options]        Start the HTTP server (default command)
  redproxy generate-key [--path <file>]
  redproxy generate-secret          Print a fresh random TOTP secret and otpauth URI
  redproxy show-uri                 Print the current TOTP URI and secret
  redproxy reset-password --password <pw>
  redproxy version                  Print version
  redproxy help                     Print this help

Serve options:
  --host <addr>                 Bind address for the user portal (default 0.0.0.0)
  --port <port>                 User portal HTTP port (default 3000)
  --admin-host <addr>           Bind address for the admin portal (default 127.0.0.1)
  --admin-port <port>           Admin portal HTTP port (default user port + 1)
  --no-admin                    Disable the admin portal entirely
  --data-dir <dir>              Data directory (default ./data)
  --public-url <url>            URL written into generated extensions
  --session-ttl <seconds>       Max session TTL (default 3600)
  --idle <seconds>              Idle timeout for extension heartbeats (default 90)
  --enrollment-ttl <seconds>    Single-use CRX token lifetime (default 120)
  --max-devices <n>             Concurrent sessions (default 2)
  --auth-mode <password|totp|totp_password>       Admin portal login mode
  --user-auth-mode <password|totp|totp_password>  User portal login mode
  --cookie-secure               Force Secure cookies
  --no-cookie-secure            Disable Secure cookies
  --allow-insecure-http         Allow extension token distribution over HTTP
  --trust-proxy                 Trust X-Forwarded-For
  --static-dir <dir>            Override web UI directory
  --template-dir <dir>          Override extension template directory

The user portal and the admin portal are two separate sites with separate
cookies and separate login sessions.

Environment variables are also supported; see .env.example and README.
`;
}

async function serve(flags: Record<string, string | boolean>): Promise<void> {
  applyServeEnv(flags);
  const config: AppConfig = loadConfig();
  const { userApp, adminApp } = createApp({ config });

  const userServer = userApp.listen(config.port, config.host, () => {
    console.log(`[RedProxy] user portal:  http://${config.host}:${config.port}/`);
    console.log(`[RedProxy] public base URL: ${config.publicBaseUrl}`);
    console.log(`[RedProxy] data dir: ${config.dataDir}`);
  });

  let adminServer: import('node:http').Server | null = null;
  if (adminApp) {
    adminServer = adminApp.listen(config.adminPort, config.adminHost, () => {
      console.log(`[RedProxy] admin portal: http://${config.adminHost}:${config.adminPort}/`);
      console.log(`[RedProxy] admin login mode: ${config.adminAuthMode}`);
      if (config.adminHost === '0.0.0.0') {
        console.log('[RedProxy] NOTE: the admin portal is bound to all interfaces; protect it with a firewall or set ADMIN_HOST=127.0.0.1.');
      }
    });
  } else {
    console.log('[RedProxy] admin portal disabled (ADMIN_ENABLED=false)');
  }

  const shutdown = (signal: string): void => {
    console.log(`[RedProxy] received ${signal}, shutting down`);
    let pending = adminServer ? 2 : 1;
    const done = (): void => {
      pending -= 1;
      if (pending <= 0) process.exit(0);
    };
    userServer.close(done);
    adminServer?.close(done);
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

function generateSecret(): void {
  const secret = randomBase32Secret();
  const uri = buildOtpAuthUri(secret);
  console.log(`TOTP secret: ${secret}`);
  console.log(`otpauth URI: ${uri}`);
  console.log('Import the URI into an authenticator app, or set ADMIN_TOTP_SECRET before first start.');
}

function showUri(flags: Record<string, string | boolean>): void {
  const dataDir = flagString(flags, 'data-dir') ? path.resolve(flagString(flags, 'data-dir')!) : path.resolve('./data');
  process.env.DATA_DIR = dataDir;
  const config = loadConfig();
  const settings = new SettingsService(config);
  const secret = settings.get().totpSecretBase32;
  console.log(`TOTP secret: ${secret}`);
  console.log(`otpauth URI: ${buildOtpAuthUri(secret)}`);
}

function resetPassword(flags: Record<string, string | boolean>): void {
  const password = flagString(flags, 'password');
  if (!password || password.length < 12) {
    console.error('--password <pw> is required and must be at least 12 characters');
    process.exitCode = 1;
    return;
  }
  const dataDir = flagString(flags, 'data-dir') ? path.resolve(flagString(flags, 'data-dir')!) : path.resolve('./data');
  process.env.DATA_DIR = dataDir;
  const config = loadConfig();
  ensureDataDir(config);
  const settings = new SettingsService(config);
  settings.setPassword(password);
  console.log(`Admin password updated in ${path.join(dataDir, 'settings.json')}`);
}

async function generateKey(flags: Record<string, string | boolean>): Promise<void> {
  const config = loadConfig();
  ensureDataDir(config);
  const keyPath = flagString(flags, 'path') ? path.resolve(flagString(flags, 'path')!) : config.crxPrivateKeyPath;
  if (fs.existsSync(keyPath)) {
    console.log(`CRX private key already exists: ${keyPath}`);
    return;
  }
  await ensureCrxPrivateKey(keyPath, config.crxKeyBits);
  console.log(`Generated CRX private key: ${keyPath}`);
}

export async function runCli(argv: string[]): Promise<void> {
  const { command, flags } = parseArgs(argv);

  if (flags.help && command === 'serve') {
    console.log(helpText());
    return;
  }
  if (flags.version) {
    console.log(VERSION);
    return;
  }

  switch (command) {
    case 'serve':
    case 'start':
      await serve(flags);
      return;
    case 'generate-key':
      await generateKey(flags);
      return;
    case 'generate-secret':
      generateSecret();
      return;
    case 'show-uri':
    case 'show-otp':
      showUri(flags);
      return;
    case 'reset-password':
      resetPassword(flags);
      return;
    case 'version':
      console.log(VERSION);
      return;
    case 'help':
      console.log(helpText());
      return;
    default:
      console.error(`Unknown command: ${command}\n`);
      console.log(helpText());
      process.exitCode = 1;
  }
}
