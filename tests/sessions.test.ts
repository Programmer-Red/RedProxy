import crypto from 'node:crypto';
import fs from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../server/src/audit';
import { NodeService } from '../server/src/nodes';
import { ConcurrentDeviceLimitError, InvalidExtensionTokenError, SessionService } from '../server/src/sessions';
import { toTestConfig } from '../server/src/config';
import { SAMPLE_NODE, tmpDir } from './helpers';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

function makeServices(now: () => number, overrides: Record<string, unknown> = {}) {
  const dataDir = tmpDir();
  tempDirs.push(dataDir);
  const config = toTestConfig({ dataDir, ...overrides });
  const audit = new AuditLog();
  const nodes = new NodeService(now);
  const sessions = new SessionService(config, nodes, audit, now);
  nodes.create(SAMPLE_NODE);
  return { config, audit, nodes, sessions };
}

function createInput(deviceId: string) {
  return {
    ownerHash: crypto.createHash('sha256').update('owner').digest('hex'),
    deviceId,
    nodeId: SAMPLE_NODE.id,
    ttlSeconds: 60,
    ip: '127.0.0.1',
    userAgent: 'vitest',
  };
}

describe('session lifecycle', () => {
  it('expires sessions after TTL', () => {
    let now = 1_700_000_000_000;
    const { sessions } = makeServices(() => now, { sessionTtlSeconds: 60, sessionIdleSeconds: 30 });
    const session = sessions.create(createInput('device-aaaaaaaa'));
    expect(sessions.isActive(session, now)).toBe(true);

    now += 61_000;
    expect(sessions.sweep()).toBe(1);
    expect(sessions.toPublic(session, now).state).toBe('expired');
    expect(session.revokedReason).toBe('ttl_expired');
  });

  it('treats idle sessions as expired', () => {
    let now = 1_700_000_000_000;
    const { sessions } = makeServices(() => now, { sessionTtlSeconds: 600, sessionIdleSeconds: 30 });
    sessions.create(createInput('device-bbbbbbbb'));
    now += 31_000;
    expect(sessions.sweep()).toBe(1);
    expect(sessions.listPublic()[0]?.state).toBe('expired');
  });

  it('heartbeat keeps an active session alive', () => {
    let now = 1_700_000_000_000;
    const { sessions } = makeServices(() => now, { sessionTtlSeconds: 600, sessionIdleSeconds: 30 });
    const session = sessions.create(createInput('device-cccccccc'));
    now += 20_000;
    const token = sessions.issueExtensionToken(session.id);
    const heartbeat = sessions.heartbeatByExtensionToken(token, '127.0.0.1');
    expect(heartbeat.session.id).toBe(session.id);
    expect(heartbeat.expiresAt).toBe(session.expiresAt);
    now += 20_000;
    expect(sessions.isActive(session, now)).toBe(true);
  });

  it('replacing the same device revokes the old session', () => {
    const { sessions } = makeServices(() => Date.now());
    const first = sessions.create(createInput('device-dddddddd'));
    const second = sessions.create(createInput('device-dddddddd'));
    expect(first.revoked).toBe(true);
    expect(first.revokedReason).toBe('replaced_by_new_session');
    expect(second.revoked).toBe(false);
  });

  it('enforces the concurrent device limit', () => {
    const { sessions } = makeServices(() => Date.now(), { maxConcurrentDevices: 2 });
    sessions.create(createInput('device-11111111'));
    sessions.create(createInput('device-22222222'));
    expect(() => sessions.create(createInput('device-33333333'))).toThrow(ConcurrentDeviceLimitError);
  });

  it('revokes a session by extension token', () => {
    const { sessions } = makeServices(() => Date.now());
    const session = sessions.create(createInput('device-eeeeeeee'));
    const token = sessions.issueExtensionToken(session.id);
    const revoked = sessions.revoke(session.id, 'admin_revoked');
    expect(revoked?.revoked).toBe(true);
    expect(() => sessions.heartbeatByExtensionToken(token, '127.0.0.1')).toThrow(InvalidExtensionTokenError);
  });

  it('invalidates an extension token when the session is revoked', () => {
    const { sessions } = makeServices(() => Date.now());
    const session = sessions.create(createInput('device-ffffffff'));
    const token = sessions.issueExtensionToken(session.id);
    sessions.heartbeatByExtensionToken(token, '127.0.0.1');
    sessions.revokeByExtensionToken(token, 'page_revoke', '127.0.0.1');
    expect(() => sessions.heartbeatByExtensionToken(token, '127.0.0.1')).toThrow(InvalidExtensionTokenError);
  });
});
