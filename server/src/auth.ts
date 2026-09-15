import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import * as OTPAuth from 'otpauth';
import type { AppConfig, AuthSessionRecord } from './types';

const BASE32_RE = /^[A-Z2-7]+=*$/;
const TOTP_ISSUER = 'RedProxy';
const TOTP_LABEL = 'admin';

export interface TotpMaterial {
  secretBase32: string;
  otpauthUri: string;
  generated: boolean;
}

export function normalizeTotpSecret(raw: string): string {
  const normalized = raw.trim().replace(/\s+/g, '').toUpperCase();
  if (normalized.length < 16 || normalized.length > 128 || !BASE32_RE.test(normalized)) {
    throw new Error('ADMIN_TOTP_SECRET must be a Base32 string (A-Z, 2-7) with length 16..128');
  }
  return normalized;
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

export function loadOrCreateTotpSecret(config: AppConfig): TotpMaterial {
  let secretBase32 = config.adminTotpSecret ? normalizeTotpSecret(config.adminTotpSecret) : '';
  const secretFile = path.join(config.dataDir, 'totp-secret.txt');
  let generated = false;

  if (!secretBase32) {
    if (fs.existsSync(secretFile)) {
      secretBase32 = normalizeTotpSecret(fs.readFileSync(secretFile, 'utf8'));
    } else {
      secretBase32 = new OTPAuth.Secret({ size: 20 }).base32;
      fs.writeFileSync(secretFile, `${secretBase32}\n`, { mode: 0o600 });
      generated = true;
      console.log(`[RedProxy] generated TOTP secret at ${secretFile}`);
    }
  }

  const otpauthUri = buildOtpAuthUri(secretBase32);
  if (generated) {
    console.log(`[RedProxy] first-run TOTP setup URI (keep secret): ${otpauthUri}`);
  }
  return { secretBase32, otpauthUri, generated };
}

export function verifyTotp(secretBase32: string, token: string, timestamp?: number): boolean {
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
    const delta = totp.validate({ token, timestamp: timestamp === undefined ? Date.now() : timestamp, window: 1 });
    return delta !== null;
  } catch {
    return false;
  }
}

export interface LoginRateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
  attemptsRemaining: number;
}

export class LoginRateLimiter {
  private attempts = new Map<string, number[]>();

  constructor(
    private readonly maxAttempts: number,
    private readonly windowSeconds: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  check(key: string): LoginRateLimitResult {
    const cutoff = this.now() - this.windowSeconds * 1000;
    const recent = (this.attempts.get(key) || []).filter(ts => ts > cutoff);
    this.attempts.set(key, recent);
    if (recent.length >= this.maxAttempts) {
      const oldest = recent[0] ?? this.now();
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((oldest + this.windowSeconds * 1000 - this.now()) / 1000)),
        attemptsRemaining: 0,
      };
    }
    return { allowed: true, retryAfterSeconds: 0, attemptsRemaining: this.maxAttempts - recent.length };
  }

  recordFailure(key: string): void {
    const now = this.now();
    const cutoff = now - this.windowSeconds * 1000;
    const recent = (this.attempts.get(key) || []).filter(ts => ts > cutoff);
    recent.push(now);
    this.attempts.set(key, recent);
  }

  clear(key: string): void {
    this.attempts.delete(key);
  }
}

export class AuthService {
  private sessions = new Map<string, AuthSessionRecord>();

  constructor(
    private readonly config: AppConfig,
    private readonly now: () => number = () => Date.now(),
  ) {}

  hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  createSession(): { token: string; record: AuthSessionRecord } {
    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = this.hashToken(token);
    const now = this.now();
    const record: AuthSessionRecord = {
      tokenHash,
      createdAt: now,
      expiresAt: now + this.config.authSessionTtlSeconds * 1000,
      lastSeenAt: now,
    };
    this.sessions.set(tokenHash, record);
    return { token, record };
  }

  validateToken(token: string | undefined | null): AuthSessionRecord | null {
    if (!token) return null;
    const tokenHash = this.hashToken(token);
    const record = this.sessions.get(tokenHash);
    if (!record) return null;
    const now = this.now();
    if (record.expiresAt <= now) {
      this.sessions.delete(tokenHash);
      return null;
    }
    record.lastSeenAt = now;
    return record;
  }

  revokeToken(token: string | undefined | null): void {
    if (!token) return;
    this.sessions.delete(this.hashToken(token));
  }
}

export function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+([A-Za-z0-9._~+/=-]+)$/i.exec(header.trim());
  return match?.[1] ?? null;
}
