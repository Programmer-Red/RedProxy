import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import * as OTPAuth from 'otpauth';
import QRCode from 'qrcode';
import type { AdminSettings, AppConfig, AuthMode } from './types';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const PASSWORD_KEY_LENGTH = 64;
const TOTP_ISSUER = 'RedProxy';
const TOTP_LABEL = 'admin';

/** Password shipped on first boot. The admin is forced to change it. */
export const DEFAULT_ADMIN_USERNAME = 'admin';
export const DEFAULT_ADMIN_PASSWORD = 'redproxy';

export function randomBase32Secret(bytes = 20): string {
  const buffer = crypto.randomBytes(bytes);
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

export function normalizeTotpSecret(raw: string): string {
  const normalized = raw.trim().replace(/\s+/g, '').toUpperCase();
  if (normalized.length < 16 || normalized.length > 128 || !/^[A-Z2-7]+=*$/.test(normalized)) {
    throw new Error('TOTP secret must be a Base32 string (A-Z, 2-7) with length 16..128');
  }
  return normalized.replace(/=+$/, '');
}

export function buildOtpAuthUri(secretBase32: string, label = TOTP_LABEL): string {
  const totp = new OTPAuth.TOTP({
    issuer: TOTP_ISSUER,
    label,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secretBase32),
  });
  return totp.toString();
}

export async function buildQrDataUrl(text: string): Promise<string> {
  return QRCode.toDataURL(text, {
    errorCorrectionLevel: 'M',
    margin: 1,
    width: 320,
    color: { dark: '#000000', light: '#ffffff' },
  });
}

export function verifyTotp(secretBase32: string, token: string, timestamp = Date.now()): boolean {
  if (!/^\d{6}$/.test(token)) return false;
  const totp = new OTPAuth.TOTP({
    issuer: TOTP_ISSUER,
    label: TOTP_LABEL,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secretBase32),
  });
  try {
    return totp.validate({ token, timestamp, window: 1 }) !== null;
  } catch {
    return false;
  }
}

export function hashPassword(password: string, salt?: string): { hash: string; salt: string } {
  const actualSalt = salt ?? crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, actualSalt, PASSWORD_KEY_LENGTH).toString('hex');
  return { hash, salt: actualSalt };
}

export function verifyPassword(password: string, hash: string | null, salt: string | null): boolean {
  if (!hash || !salt) return false;
  const candidate = crypto.scryptSync(password, salt, PASSWORD_KEY_LENGTH);
  const expected = Buffer.from(hash, 'hex');
  if (candidate.length !== expected.length) return false;
  return crypto.timingSafeEqual(candidate, expected);
}

export interface PublicSettings {
  username: string;
  adminAuthMode: AuthMode;
  userAuthMode: AuthMode;
  mustChangePassword: boolean;
  hasTotp: boolean;
  totpSecretBase32: string | null;
  otpauthUri: string | null;
  qrDataUrl: string | null;
  passwordUpdatedAt: number | null;
  defaults: { username: string; password: string };
}

export class SettingsService {
  private settings: AdminSettings;
  private readonly filePath: string;

  constructor(
    private readonly config: AppConfig,
    private readonly now: () => number = () => Date.now(),
    seedSecret: string | null = null,
  ) {
    this.filePath = path.join(config.dataDir, 'settings.json');
    this.settings = this.load(seedSecret);
  }

  private load(seedSecret: string | null): AdminSettings {
    const timestamp = this.now();
    if (fs.existsSync(this.filePath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.filePath, 'utf8')) as Partial<AdminSettings> & { authMode?: AuthMode };
        if (raw.totpSecretBase32 || raw.passwordHash) {
          const legacyMode = raw.authMode;
          return {
            username: (raw.username || this.config.adminUsername || DEFAULT_ADMIN_USERNAME).trim(),
            adminAuthMode: normalizeMode(raw.adminAuthMode ?? legacyMode, this.config.adminAuthMode, 'password'),
            userAuthMode: normalizeMode(raw.userAuthMode, this.config.userAuthMode, 'totp'),
            totpSecretBase32: raw.totpSecretBase32 ? normalizeTotpSecret(raw.totpSecretBase32) : randomBase32Secret(),
            passwordHash: raw.passwordHash ?? null,
            passwordSalt: raw.passwordSalt ?? null,
            passwordUpdatedAt: raw.passwordUpdatedAt ?? null,
            mustChangePassword: raw.mustChangePassword ?? !raw.passwordHash,
            createdAt: raw.createdAt ?? timestamp,
            updatedAt: raw.updatedAt ?? timestamp,
          };
        }
      } catch (error) {
        console.error(`[RedProxy] failed to read ${this.filePath}, regenerating settings:`, error);
      }
    }

    const seededSecret = seedSecret
      ? normalizeTotpSecret(seedSecret)
      : this.config.adminTotpSecret
        ? normalizeTotpSecret(this.config.adminTotpSecret)
        : randomBase32Secret();

    const initialPassword = this.config.adminPassword || DEFAULT_ADMIN_PASSWORD;
    const seededPassword = hashPassword(initialPassword);
    const settings: AdminSettings = {
      username: (this.config.adminUsername || DEFAULT_ADMIN_USERNAME).trim(),
      adminAuthMode: this.config.adminAuthMode,
      userAuthMode: this.config.userAuthMode,
      totpSecretBase32: seededSecret,
      passwordHash: seededPassword.hash,
      passwordSalt: seededPassword.salt,
      passwordUpdatedAt: timestamp,
      mustChangePassword: initialPassword === DEFAULT_ADMIN_PASSWORD,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    this.settings = settings;
    this.persist();
    console.log(
      `[RedProxy] initialized settings. default admin account: ${settings.username} / ${DEFAULT_ADMIN_PASSWORD} (change it after first login)`,
    );
    return settings;
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(this.filePath, `${JSON.stringify(this.settings, null, 2)}\n`, { mode: 0o600 });
  }

  get(): AdminSettings {
    return this.settings;
  }

  async toPublic(): Promise<PublicSettings> {
    const hasTotp = Boolean(this.settings.totpSecretBase32);
    const uri = hasTotp ? buildOtpAuthUri(this.settings.totpSecretBase32, this.settings.username) : null;
    return {
      username: this.settings.username,
      adminAuthMode: this.settings.adminAuthMode,
      userAuthMode: this.settings.userAuthMode,
      mustChangePassword: this.settings.mustChangePassword,
      hasTotp,
      totpSecretBase32: hasTotp ? this.settings.totpSecretBase32 : null,
      otpauthUri: uri,
      qrDataUrl: uri ? await buildQrDataUrl(uri) : null,
      passwordUpdatedAt: this.settings.passwordUpdatedAt,
      defaults: { username: DEFAULT_ADMIN_USERNAME, password: DEFAULT_ADMIN_PASSWORD },
    };
  }

  // ------------------------------------------------------------------ auth
  verifyTotp(token: string): boolean {
    return verifyTotp(this.settings.totpSecretBase32, token, this.now());
  }

  verifyPassword(password: string): boolean {
    return verifyPassword(password, this.settings.passwordHash, this.settings.passwordSalt);
  }

  /**
   * Verify a credential pair for the given realm. Each mode has its own rules,
   * so the admin can independently decide how the user portal and the admin
   * portal authenticate.
   */
  verifyLogin(mode: AuthMode, input: { token?: string; password?: string; username?: string }): { ok: boolean; reason?: string } {
    if (input.username && input.username.trim() && input.username.trim() !== this.settings.username) {
      return { ok: false, reason: 'bad_credentials' };
    }
    const tokenOk = input.token ? this.verifyTotp(input.token) : false;
    const passwordOk = input.password ? this.verifyPassword(input.password) : false;

    switch (mode) {
      case 'password':
        return passwordOk ? { ok: true } : { ok: false, reason: 'bad_credentials' };
      case 'totp':
        return tokenOk ? { ok: true } : { ok: false, reason: 'bad_totp' };
      case 'totp_password':
        if (!tokenOk || !passwordOk) return { ok: false, reason: 'bad_credentials' };
        return { ok: true };
      default:
        return { ok: false, reason: 'bad_mode' };
    }
  }

  setAdminAuthMode(mode: AuthMode): AdminSettings {
    if ((mode === 'password' || mode === 'totp_password') && !this.settings.passwordHash) {
      throw new Error('password_required');
    }
    if ((mode === 'totp' || mode === 'totp_password') && !this.settings.totpSecretBase32) {
      throw new Error('totp_required');
    }
    this.settings.adminAuthMode = mode;
    this.settings.updatedAt = this.now();
    this.persist();
    return this.settings;
  }

  setUserAuthMode(mode: AuthMode): AdminSettings {
    if ((mode === 'password' || mode === 'totp_password') && !this.settings.passwordHash) {
      throw new Error('password_required');
    }
    if ((mode === 'totp' || mode === 'totp_password') && !this.settings.totpSecretBase32) {
      throw new Error('totp_required');
    }
    this.settings.userAuthMode = mode;
    this.settings.updatedAt = this.now();
    this.persist();
    return this.settings;
  }

  setUsername(username: string): AdminSettings {
    this.settings.username = username.trim();
    this.settings.updatedAt = this.now();
    this.persist();
    return this.settings;
  }

  setPassword(password: string): AdminSettings {
    if (password.length < 8) throw new Error('password_too_short');
    const { hash, salt } = hashPassword(password);
    this.settings.passwordHash = hash;
    this.settings.passwordSalt = salt;
    this.settings.passwordUpdatedAt = this.now();
    this.settings.mustChangePassword = false;
    this.settings.updatedAt = this.now();
    this.persist();
    return this.settings;
  }

  clearPassword(): AdminSettings {
    this.settings.passwordHash = null;
    this.settings.passwordSalt = null;
    this.settings.passwordUpdatedAt = null;
    if (this.settings.adminAuthMode === 'password' || this.settings.adminAuthMode === 'totp_password') {
      this.settings.adminAuthMode = 'totp';
    }
    if (this.settings.userAuthMode === 'password' || this.settings.userAuthMode === 'totp_password') {
      this.settings.userAuthMode = 'totp';
    }
    this.settings.updatedAt = this.now();
    this.persist();
    return this.settings;
  }

  regenerateTotpSecret(): AdminSettings {
    this.settings.totpSecretBase32 = randomBase32Secret();
    this.settings.updatedAt = this.now();
    this.persist();
    return this.settings;
  }
}

function normalizeMode(value: string | undefined, fallback: AuthMode, defaultMode: AuthMode): AuthMode {
  if (value === 'password' || value === 'totp' || value === 'totp_password') return value;
  if (value === 'admin_password') return 'password';
  if (value) return fallback;
  return fallback ?? defaultMode;
}
