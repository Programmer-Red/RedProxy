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
}

export class SessionService {
  private sessions = new Map<string, SessionRecord>();
  private tokenIndex = new Map<string, string>();

  private readonly extensionTokenSecret = crypto.randomBytes(32);

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

    const id = crypto.randomUUID();
    const session: SessionRecord = {
      id,
      ownerHash: input.ownerHash,
      deviceId: input.deviceId,
      nodeId: node.id,
      extensionTokenHash: null,
      extensionTokenNonce: crypto.randomBytes(16).toString('hex'),
      extensionTokenIssuedAt: null,
      createdAt: now,
      expiresAt: now + input.ttlSeconds * 1000,
      lastHeartbeatAt: now,
      revoked: false,
      revokedAt: null,
      revokedReason: null,
      ip: input.ip,
      userAgent: input.userAgent,
    };
    this.sessions.set(id, session);
    session.extensionTokenHash = this.hashToken(this.generateExtensionToken(session));
    this.tokenIndex.set(session.extensionTokenHash, session.id);
    this.audit.record('session_created', {
      sessionId: id,
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
      revoked: session.revoked,
      revokedAt: session.revokedAt,
      revokedReason: session.revokedReason,
      state,
      remainingSeconds: state === 'active' ? remainingSeconds : 0,
    };
  }

  issueExtensionToken(sessionId: string): string {
    const session = this.sessions.get(sessionId);
    if (!session) throw new SessionNotFoundError();
    if (!this.isActive(session, this.now())) throw new InvalidExtensionTokenError('session_inactive');
    const raw = this.generateExtensionToken(session);
    const tokenHash = this.hashToken(raw);
    session.extensionTokenHash = tokenHash;
    session.extensionTokenIssuedAt = this.now();
    this.tokenIndex.set(tokenHash, session.id);
    this.audit.record('extension_token_issued', {
      sessionId: session.id,
      deviceId: session.deviceId,
      nodeId: session.nodeId,
    });
    return raw;
  }

  heartbeatByExtensionToken(rawToken: string, ip: string): HeartbeatResult {
    const session = this.requireActiveByToken(rawToken);
    const now = this.now();
    session.lastHeartbeatAt = now;
    this.audit.record('extension_heartbeat', {
      sessionId: session.id,
      deviceId: session.deviceId,
      nodeId: session.nodeId,
      ip,
    });
    return { session, expiresAt: session.expiresAt };
  }

  revokeByExtensionToken(rawToken: string, reason: string, ip: string): SessionRecord {
    const session = this.requireByToken(rawToken);
    if (!session.revoked) {
      this.revoke(session.id, reason, ip);
    }
    return session;
  }

  revoke(sessionId: string, reason: string, ip?: string): SessionRecord | null {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    if (!session.revoked) {
      session.revoked = true;
      session.revokedAt = this.now();
      session.revokedReason = reason;
      this.invalidateTokenIndex(session);
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
    const session = this.getActiveCurrentForOwner(ownerHash);
    if (!session) return null;
    return this.revoke(session.id, reason, ip);
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
        session.revoked = true;
        session.revokedAt = now;
        session.revokedReason = 'ttl_expired';
        this.invalidateTokenIndex(session);
        this.audit.record('session_expired', {
          sessionId: session.id,
          deviceId: session.deviceId,
          nodeId: session.nodeId,
          reason: 'ttl_expired',
        });
        changed += 1;
      } else if (session.lastHeartbeatAt + this.config.sessionIdleSeconds * 1000 <= now) {
        session.revoked = true;
        session.revokedAt = now;
        session.revokedReason = 'idle_timeout';
        this.invalidateTokenIndex(session);
        this.audit.record('session_expired', {
          sessionId: session.id,
          deviceId: session.deviceId,
          nodeId: session.nodeId,
          reason: 'idle_timeout',
        });
        changed += 1;
      }
    }
    return changed;
  }

  private requireByToken(rawToken: string): SessionRecord {
    const tokenHash = this.hashToken(rawToken);
    const sessionId = this.tokenIndex.get(tokenHash);
    const session = sessionId ? this.sessions.get(sessionId) : undefined;
    if (!session || session.extensionTokenHash !== tokenHash) {
      throw new InvalidExtensionTokenError('unknown_token');
    }
    return session;
  }

  private requireActiveByToken(rawToken: string): SessionRecord {
    const session = this.requireByToken(rawToken);
    const now = this.now();
    if (session.revoked) throw new InvalidExtensionTokenError('revoked');
    if (session.expiresAt <= now) {
      this.revoke(session.id, 'ttl_expired');
      throw new InvalidExtensionTokenError('expired');
    }
    if (session.lastHeartbeatAt + this.config.sessionIdleSeconds * 1000 <= now) {
      this.revoke(session.id, 'idle_timeout');
      throw new InvalidExtensionTokenError('idle');
    }
    return session;
  }

  private generateExtensionToken(session: SessionRecord): string {
    return crypto
      .createHmac('sha256', this.extensionTokenSecret)
      .update(`v1:${session.id}:${session.deviceId}:${session.extensionTokenNonce}`)
      .digest('base64url');
  }

  private invalidateTokenIndex(session: SessionRecord): void {
    if (session.extensionTokenHash) {
      this.tokenIndex.delete(session.extensionTokenHash);
    }
    session.extensionTokenHash = null;
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
    return 'active';
  }
}
