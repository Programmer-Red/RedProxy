import crypto from 'node:crypto';
import { AuditLog } from './audit';
import type { NodeService } from './nodes';
import type { AppConfig, PublicSession, SessionRecord } from './types';

export class ConcurrentDeviceLimitError extends Error {
  constructor(public readonly maxDevices: number) {
    super(`concurrent_device_limit:${maxDevices}`);
    this.name = 'ConcurrentDeviceLimitError';
  }
}

export class SessionNotFoundError extends Error {
  constructor() {
    super('session_not_found');
    this.name = 'SessionNotFoundError';
  }
}

export class InvalidExtensionTokenError extends Error {
  constructor(public readonly reason: string) {
    super(`invalid_extension_token:${reason}`);
    this.name = 'InvalidExtensionTokenError';
  }
}

export interface CreateSessionInput {
  ownerHash: string;
  deviceId: string;
  nodeId: string;
  ttlSeconds: number;
  ip: string;
  userAgent: string;
}

export interface HeartbeatResult {
  session: SessionRecord;
  expiresAt: number;
  rotatedToken: string | null;
  enrolled: boolean;
}

export class SessionService {
  private sessions = new Map<string, SessionRecord>();
  private tokenIndex = new Map<string, string>();

  constructor(
    private readonly config: AppConfig,
    private readonly nodes: NodeService,
    private readonly audit: AuditLog,
    private readonly now: () => number = () => Date.now(),
  ) {}

  create(input: CreateSessionInput): SessionRecord {
    const node = this.nodes.requireEnabled(input.nodeId);
    const now = this.now();

    const sameDevice = [...this.sessions.values()].filter(
      session => session.deviceId === input.deviceId && session.ownerHash === input.ownerHash && this.isActive(session, now),
    );
    for (const session of sameDevice) {
      this.revoke(session.id, 'replaced_by_new_session', input.ip);
    }

    const activeCount = [...this.sessions.values()].filter(session => this.isActive(session, now)).length;
    if (activeCount >= this.config.maxConcurrentDevices) {
      throw new ConcurrentDeviceLimitError(this.config.maxConcurrentDevices);
    }

    const session: SessionRecord = {
      id: crypto.randomUUID(),
      ownerHash: input.ownerHash,
      deviceId: input.deviceId,
      nodeId: node.id,
      enrollmentTokenHash: null,
      enrollmentTokenExpiresAt: null,
      accessTokenHash: null,
      previousAccessTokenHash: null,
      previousAccessTokenValidUntil: null,
      tokenNonce: crypto.randomBytes(16).toString('hex'),
      createdAt: now,
      expiresAt: now + input.ttlSeconds * 1000,
      lastHeartbeatAt: now,
      revoked: false,
      revokedAt: null,
      revokedReason: null,
      ip: input.ip,
      userAgent: input.userAgent,
    };
    this.sessions.set(session.id, session);
    this.audit.record('session_created', {
      sessionId: session.id,
      deviceId: input.deviceId,
      nodeId: node.id,
      ip: input.ip,
      meta: { ttlSeconds: input.ttlSeconds, maxConcurrentDevices: this.config.maxConcurrentDevices },
    });
    return session;
  }

  listAll(): SessionRecord[] {
    return [...this.sessions.values()].sort((a, b) => b.createdAt - a.createdAt);
  }

  listPublic(): PublicSession[] {
    const now = this.now();
    return this.listAll().map(session => this.toPublic(session, now));
  }

  get(id: string): SessionRecord | undefined {
    return this.sessions.get(id);
  }

  getCurrentForOwner(ownerHash: string): SessionRecord | null {
    const candidates = this.listAll().filter(session => session.ownerHash === ownerHash);
    return candidates.find(session => this.isActive(session, this.now())) ?? candidates[0] ?? null;
  }

  getActiveCurrentForOwner(ownerHash: string): SessionRecord | null {
    return this.listAll().find(session => session.ownerHash === ownerHash && this.isActive(session, this.now())) ?? null;
  }

  toPublic(session: SessionRecord, now = this.now()): PublicSession {
    const node = this.nodes.get(session.nodeId);
    const state = this.stateOf(session, now);
    const remainingSeconds = Math.max(0, Math.ceil((session.expiresAt - now) / 1000));
    return {
      id: session.id,
      deviceId: session.deviceId,
      nodeId: session.nodeId,
      nodeName: node?.name ?? session.nodeId,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      lastHeartbeatAt: session.lastHeartbeatAt,
      enrolled: session.accessTokenHash !== null,
      revoked: session.revoked,
      revokedAt: session.revokedAt,
      revokedReason: session.revokedReason,
      state,
      remainingSeconds: state === 'active' || state === 'pending' ? remainingSeconds : 0,
      ip: session.ip,
    };
  }

  /**
   * Mint the single-use enrollment token embedded into a freshly generated CRX.
   * A previous unconsumed enrollment token is invalidated so the newest download wins.
   */
  issueExtensionToken(sessionId: string): string {
    const session = this.sessions.get(sessionId);
    if (!session) throw new SessionNotFoundError();
    if (!this.isActive(session, this.now())) throw new InvalidExtensionTokenError('session_inactive');
    this.removeTokenHash(session.enrollmentTokenHash);
    const raw = crypto.randomBytes(24).toString('base64url');
    session.enrollmentTokenHash = this.hashToken(raw);
    session.enrollmentTokenExpiresAt = this.now() + this.config.enrollmentTtlSeconds * 1000;
    this.tokenIndex.set(session.enrollmentTokenHash, session.id);
    this.audit.record('extension_enrollment_issued', {
      sessionId: session.id,
      deviceId: session.deviceId,
      nodeId: session.nodeId,
      meta: { expiresAt: session.enrollmentTokenExpiresAt, singleUse: true },
    });
    return raw;
  }

  /**
   * Heartbeat used by the extension. The first call consumes the single-use
   * enrollment token from the CRX and rotates it to a server-only access token.
   * Every later call can rotate the access token again; the previous token stays
   * valid only for a short grace window so a crashed service worker can recover.
   */
  heartbeatByExtensionToken(rawToken: string, ip: string): HeartbeatResult {
    const hash = this.hashToken(rawToken);
    const session = this.findByHash(hash);
    if (!session) throw new InvalidExtensionTokenError('unknown_token');
    const now = this.now();
    this.assertActive(session, now);

    if (session.enrollmentTokenHash && hash === session.enrollmentTokenHash) {
      if (!session.enrollmentTokenExpiresAt || session.enrollmentTokenExpiresAt <= now) {
        this.removeTokenHash(session.enrollmentTokenHash);
        session.enrollmentTokenHash = null;
        session.enrollmentTokenExpiresAt = null;
        throw new InvalidExtensionTokenError('enrollment_expired');
      }
      this.removeTokenHash(session.enrollmentTokenHash);
      session.enrollmentTokenHash = null;
      session.enrollmentTokenExpiresAt = null;
      const accessToken = this.rotateAccessToken(session, now);
      session.lastHeartbeatAt = now;
      this.audit.record('extension_enrolled', {
        sessionId: session.id,
        deviceId: session.deviceId,
        nodeId: session.nodeId,
        ip,
        meta: { singleUseTokenConsumed: true },
      });
      return { session, expiresAt: session.expiresAt, rotatedToken: accessToken, enrolled: true };
    }

    if (session.accessTokenHash && hash === session.accessTokenHash) {
      const rotatedToken = this.rotateAccessToken(session, now);
      session.lastHeartbeatAt = now;
      this.audit.record('extension_heartbeat', {
        sessionId: session.id,
        deviceId: session.deviceId,
        nodeId: session.nodeId,
        ip,
        meta: { rotated: true },
      });
      return { session, expiresAt: session.expiresAt, rotatedToken, enrolled: false };
    }

    if (
      session.previousAccessTokenHash &&
      hash === session.previousAccessTokenHash &&
      session.previousAccessTokenValidUntil !== null &&
      session.previousAccessTokenValidUntil > now
    ) {
      // Recovery path: the extension missed the last rotation response but still
      // holds the previous token. Accept it once and rotate to a new token.
      const rotatedToken = this.rotateAccessToken(session, now);
      session.lastHeartbeatAt = now;
      this.audit.record('extension_heartbeat_recovered', {
        sessionId: session.id,
        deviceId: session.deviceId,
        nodeId: session.nodeId,
        ip,
      });
      return { session, expiresAt: session.expiresAt, rotatedToken, enrolled: false };
    }

    throw new InvalidExtensionTokenError('replayed_or_revoked');
  }

  revokeByExtensionToken(rawToken: string, reason: string, ip: string): SessionRecord {
    const hash = this.hashToken(rawToken);
    const session = this.findByHash(hash);
    if (!session) throw new InvalidExtensionTokenError('unknown_token');
    if (!session.revoked) this.revoke(session.id, reason, ip);
    return session;
  }

  revoke(sessionId: string, reason: string, ip?: string): SessionRecord | null {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    if (!session.revoked) {
      session.revoked = true;
      session.revokedAt = this.now();
      session.revokedReason = reason;
      this.clearAllTokens(session);
      this.audit.record('session_revoked', {
        sessionId: session.id,
        deviceId: session.deviceId,
        nodeId: session.nodeId,
        reason,
        ip,
      });
    }
    return session;
  }

  revokeCurrentForOwner(ownerHash: string, reason: string, ip?: string): SessionRecord | null {
    const session = this.getActiveCurrentForOwner(ownerHash) ?? this.getCurrentForOwner(ownerHash);
    if (!session) return null;
    return this.revoke(session.id, reason, ip);
  }

  touchCurrentForOwner(ownerHash: string, ip: string): SessionRecord | null {
    const session = this.getActiveCurrentForOwner(ownerHash);
    if (!session) return null;
    session.lastHeartbeatAt = this.now();
    this.audit.record('session_heartbeat', {
      sessionId: session.id,
      deviceId: session.deviceId,
      nodeId: session.nodeId,
      ip,
    });
    return session;
  }

  isActive(session: SessionRecord, now = this.now()): boolean {
    return !session.revoked && session.expiresAt > now && session.lastHeartbeatAt + this.config.sessionIdleSeconds * 1000 > now;
  }

  sweep(): number {
    const now = this.now();
    let changed = 0;
    for (const session of this.sessions.values()) {
      if (session.revoked) continue;
      if (session.expiresAt <= now) {
        this.markExpired(session, now, 'ttl_expired');
        changed += 1;
      } else if (session.lastHeartbeatAt + this.config.sessionIdleSeconds * 1000 <= now) {
        this.markExpired(session, now, 'idle_timeout');
        changed += 1;
      } else if (session.enrollmentTokenExpiresAt !== null && session.enrollmentTokenExpiresAt <= now && session.accessTokenHash === null) {
        this.removeTokenHash(session.enrollmentTokenHash);
        session.enrollmentTokenHash = null;
        session.enrollmentTokenExpiresAt = null;
        this.audit.record('extension_enrollment_expired', {
          sessionId: session.id,
          deviceId: session.deviceId,
          nodeId: session.nodeId,
        });
        changed += 1;
      }
    }
    return changed;
  }

  private markExpired(session: SessionRecord, now: number, reason: string): void {
    session.revoked = true;
    session.revokedAt = now;
    session.revokedReason = reason;
    this.clearAllTokens(session);
    this.audit.record('session_expired', {
      sessionId: session.id,
      deviceId: session.deviceId,
      nodeId: session.nodeId,
      reason,
    });
  }

  private assertActive(session: SessionRecord, now: number): void {
    if (session.revoked) throw new InvalidExtensionTokenError('revoked');
    if (session.expiresAt <= now) {
      this.markExpired(session, now, 'ttl_expired');
      throw new InvalidExtensionTokenError('expired');
    }
    if (session.lastHeartbeatAt + this.config.sessionIdleSeconds * 1000 <= now) {
      this.markExpired(session, now, 'idle_timeout');
      throw new InvalidExtensionTokenError('idle');
    }
  }

  private rotateAccessToken(session: SessionRecord, now: number): string {
    if (session.accessTokenHash) {
      session.previousAccessTokenHash = session.accessTokenHash;
      session.previousAccessTokenValidUntil = now + this.config.tokenGraceSeconds * 1000;
      this.tokenIndex.set(session.accessTokenHash, session.id);
    }
    const raw = crypto.randomBytes(24).toString('base64url');
    const newHash = this.hashToken(raw);
    session.accessTokenHash = newHash;
    this.tokenIndex.set(newHash, session.id);
    return raw;
  }

  private findByHash(hash: string): SessionRecord | undefined {
    const sessionId = this.tokenIndex.get(hash);
    if (!sessionId) return undefined;
    const session = this.sessions.get(sessionId);
    if (!session) {
      this.tokenIndex.delete(hash);
      return undefined;
    }
    const matches =
      session.enrollmentTokenHash === hash || session.accessTokenHash === hash || session.previousAccessTokenHash === hash;
    if (!matches) {
      this.tokenIndex.delete(hash);
      return undefined;
    }
    return session;
  }

  private clearAllTokens(session: SessionRecord): void {
    this.removeTokenHash(session.enrollmentTokenHash);
    this.removeTokenHash(session.accessTokenHash);
    this.removeTokenHash(session.previousAccessTokenHash);
    session.enrollmentTokenHash = null;
    session.enrollmentTokenExpiresAt = null;
    session.accessTokenHash = null;
    session.previousAccessTokenHash = null;
    session.previousAccessTokenValidUntil = null;
  }

  private removeTokenHash(hash: string | null): void {
    if (hash) this.tokenIndex.delete(hash);
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  private stateOf(session: SessionRecord, now: number): PublicSession['state'] {
    if (session.revoked) {
      return session.revokedReason === 'ttl_expired' || session.revokedReason === 'idle_timeout' ? 'expired' : 'revoked';
    }
    if (session.expiresAt <= now) return 'expired';
    if (session.lastHeartbeatAt + this.config.sessionIdleSeconds * 1000 <= now) return 'idle';
    if (session.accessTokenHash === null) return 'pending';
    return 'active';
  }
}
