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
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function normalizeTotpSecret(raw: string): string {
  const normalized = raw.trim().replace(/\s+/g, '').toUpperCase();
  if (normalized.length < 16 || normalized.length > 128 || !/^[A-Z2-7]+=*$/.test(normalized)) {
    throw new Error('TOTP secret must be a Base32 string (A-Z, 2-7) with length 16..128');
  }
  return normalized.replace(/=+$/, '');
}

export function buildOtpAuthUri(secretBase32: string): string {
  const totp = new OTPAuth.TOTP({
    issuer: TOTP_ISSUER,
    label: TOTP_LABEL,
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
    const delta = totp.validate({ token, timestamp, window: 1 });
    return delta !== null;
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

export interface PublicAuthSettings {
  authMode: AuthMode;
  hasPassword: boolean;
  totpSecretBase32: string;
  otpauthUri: string;
  qrDataUrl: string;
  passwordUpdatedAt: number | null;
}

export class SettingsService {
  private settings: AdminSettings;
  private readonly filePath: string;

  constructor(
    private readonly config: AppConfig,
    private readonly now: () => number = () => Date.now(),
    private readonly seedSecret: string | null = null,
  ) {
    this.filePath = path.join(config.dataDir, 'settings.json');
    this.settings = this.load();
  }

  private load(): AdminSettings {
    const timestamp = this.now();
    if (fs.existsSync(this.filePath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.filePath, 'utf8')) as Partial<AdminSettings>;
        if (raw.totpSecretBase32) {
          return {
            authMode: raw.authMode === 'totp_password' ? 'totp_password' : 'totp',
            totpSecretBase32: normalizeTotpSecret(raw.totpSecretBase32),
            passwordHash: raw.passwordHash ?? null,
            passwordSalt: raw.passwordSalt ?? null,
            passwordUpdatedAt: raw.passwordUpdatedAt ?? null,
            createdAt: raw.createdAt ?? timestamp,
            updatedAt: raw.updatedAt ?? timestamp,
          };
        }
      } catch (error) {
        console.error(`[RedProxy] failed to read ${this.filePath}, regenerating settings:`, error);
      }
    }

    const seededSecret = this.seedSecret
      ? normalizeTotpSecret(this.seedSecret)
      : this.config.adminTotpSecret
        ? normalizeTotpSecret(this.config.adminTotpSecret)
        : randomBase32Secret();
    const seededPassword = process.env.ADMIN_PASSWORD ? hashPassword(process.env.ADMIN_PASSWORD) : null;
    const settings: AdminSettings = {
      authMode: this.config.authMode,
      totpSecretBase32: seededSecret,
      passwordHash: seededPassword?.hash ?? null,
      passwordSalt: seededPassword?.salt ?? null,
      passwordUpdatedAt: seededPassword ? timestamp : null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    this.settings = settings;
    this.persist();
    if (this.seedSecret || this.config.adminTotpSecret) {
      console.log('[RedProxy] initialized TOTP settings from the configured secret');
    } else {
      console.log('[RedProxy] generated a new random TOTP secret; configure your authenticator through the admin QR page.');
    }
    return settings;
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(this.filePath, `${JSON.stringify(this.settings, null, 2)}\n`, { mode: 0o600 });
  }

  get(): AdminSettings {
    return this.settings;
  }

  getAuthMode(): AuthMode {
    return this.settings.authMode;
  }

  async toPublic(): Promise<PublicAuthSettings> {
    const uri = buildOtpAuthUri(this.settings.totpSecretBase32);
    return {
      authMode: this.settings.authMode,
      hasPassword: Boolean(this.settings.passwordHash && this.settings.passwordSalt),
      totpSecretBase32: this.settings.totpSecretBase32,
      otpauthUri: uri,
      qrDataUrl: await buildQrDataUrl(uri),
      passwordUpdatedAt: this.settings.passwordUpdatedAt,
    };
  }

  verifyUserTotp(token: string): boolean {
    return verifyTotp(this.settings.totpSecretBase32, token, this.now());
  }

  verifyUserPassword(password: string): boolean {
    return verifyPassword(password, this.settings.passwordHash, this.settings.passwordSalt);
  }

  setAuthMode(mode: AuthMode): AdminSettings {
    if (mode === 'totp_password' && !this.settings.passwordHash) {
      throw new Error('password_required');
    }
    this.settings.authMode = mode;
    this.settings.updatedAt = this.now();
    this.persist();
    return this.settings;
  }

  setPassword(password: string): AdminSettings {
    if (password.length < 12) {
      throw new Error('password_too_short');
    }
    const { hash, salt } = hashPassword(password);
    this.settings.passwordHash = hash;
    this.settings.passwordSalt = salt;
    this.settings.passwordUpdatedAt = this.now();
    this.settings.updatedAt = this.now();
    this.persist();
    return this.settings;
  }

  clearPassword(): AdminSettings {
    this.settings.passwordHash = null;
    this.settings.passwordSalt = null;
    this.settings.passwordUpdatedAt = null;
    this.settings.authMode = 'totp';
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
