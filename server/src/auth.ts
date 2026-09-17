import crypto from 'node:crypto';
import type { AppConfig, AuthRealm, AuthSessionRecord } from './types';

export class AuthService {
  private sessions = new Map<string, AuthSessionRecord>();

  constructor(
    private readonly config: AppConfig,
    private readonly now: () => number = () => Date.now(),
  ) {}

  hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  createSession(realm: AuthRealm): { token: string; record: AuthSessionRecord } {
    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = this.hashToken(token);
    const now = this.now();
    const record: AuthSessionRecord = {
      tokenHash,
      realm,
      createdAt: now,
      expiresAt: now + this.config.authSessionTtlSeconds * 1000,
      lastSeenAt: now,
    };
    this.sessions.set(tokenHash, record);
    return { token, record };
  }

  validateToken(token: string | undefined | null, realm?: AuthRealm): AuthSessionRecord | null {
    if (!token) return null;
    const tokenHash = this.hashToken(token);
    const record = this.sessions.get(tokenHash);
    if (!record) return null;
    if (realm && record.realm !== realm) return null;
    const now = this.now();
    if (record.expiresAt <= now) {
      this.sessions.delete(tokenHash);
      return null;
    }
    record.lastSeenAt = now;
    return record;
  }

  revokeToken(token: string | undefined | null, realm?: AuthRealm): void {
    if (!token) return;
    const record = this.validateToken(token, realm);
    if (!record) return;
    this.sessions.delete(record.tokenHash);
  }

  revokeRealm(realm: AuthRealm): void {
    for (const [hash, record] of this.sessions.entries()) {
      if (record.realm === realm) this.sessions.delete(hash);
    }
  }

  revokeAll(): void {
    this.sessions.clear();
  }

  sessionCount(): number {
    return this.sessions.size;
  }
}

export function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+([A-Za-z0-9._~+/=-]+)$/i.exec(header.trim());
  return match?.[1] ?? null;
}

export interface LoginAttemptDecision {
  allowed: boolean;
  retryAfterSeconds: number;
  attemptsRemaining: number;
  banned: boolean;
}

export interface BanEntry {
  ip: string;
  bannedUntil: number;
  failures: number;
  lastFailureAt: number;
}

interface AttemptState {
  failures: number[];
  bannedUntil: number;
  lastFailureAt: number;
}

export class LoginRateLimiter {
  private attempts = new Map<string, AttemptState>();

  constructor(
    private readonly maxAttempts: number,
    private readonly windowSeconds: number,
    private readonly banSeconds: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  private stateFor(key: string): AttemptState {
    const existing = this.attempts.get(key);
    if (existing) return existing;
    const created: AttemptState = { failures: [], bannedUntil: 0, lastFailureAt: 0 };
    this.attempts.set(key, created);
    return created;
  }

  private prune(state: AttemptState): void {
    const cutoff = this.now() - this.windowSeconds * 1000;
    state.failures = state.failures.filter(timestamp => timestamp > cutoff);
  }

  check(key: string): LoginAttemptDecision {
    const now = this.now();
    const state = this.stateFor(key);
    if (state.bannedUntil > now) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((state.bannedUntil - now) / 1000)),
        attemptsRemaining: 0,
        banned: true,
      };
    }
    if (state.bannedUntil !== 0 && state.bannedUntil <= now) {
      state.bannedUntil = 0;
      state.failures = [];
    }
    this.prune(state);
    if (state.failures.length >= this.maxAttempts) {
      // Defensive: if a window filled up between checks, apply the ban now.
      state.bannedUntil = this.banSeconds > 0 ? now + this.banSeconds * 1000 : 0;
      if (state.bannedUntil > now) {
        return {
          allowed: false,
          retryAfterSeconds: this.banSeconds,
          attemptsRemaining: 0,
          banned: true,
        };
      }
      return { allowed: false, retryAfterSeconds: 1, attemptsRemaining: 0, banned: false };
    }
    return {
      allowed: true,
      retryAfterSeconds: 0,
      attemptsRemaining: Math.max(0, this.maxAttempts - state.failures.length),
      banned: false,
    };
  }

  recordFailure(key: string): LoginAttemptDecision {
    const now = this.now();
    const state = this.stateFor(key);
    this.prune(state);
    state.failures.push(now);
    state.lastFailureAt = now;
    if (state.failures.length >= this.maxAttempts && this.banSeconds > 0) {
      state.bannedUntil = now + this.banSeconds * 1000;
      state.failures = [];
      return {
        allowed: false,
        retryAfterSeconds: this.banSeconds,
        attemptsRemaining: 0,
        banned: true,
      };
    }
    return {
      allowed: true,
      retryAfterSeconds: 0,
      attemptsRemaining: Math.max(0, this.maxAttempts - state.failures.length),
      banned: false,
    };
  }

  clear(key: string): void {
    this.attempts.delete(key);
  }

  listBans(): BanEntry[] {
    const now = this.now();
    const bans: BanEntry[] = [];
    for (const [ip, state] of this.attempts.entries()) {
      if (state.bannedUntil > now) {
        bans.push({
          ip,
          bannedUntil: state.bannedUntil,
          failures: state.failures.length,
          lastFailureAt: state.lastFailureAt,
        });
      }
    }
    return bans.sort((a, b) => b.bannedUntil - a.bannedUntil);
  }

  unban(key: string): boolean {
    const state = this.attempts.get(key);
    if (!state) return false;
    this.attempts.delete(key);
    return true;
  }
}
