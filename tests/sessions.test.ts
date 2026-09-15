import fs from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../server/src/audit';
import { NodeService } from '../server/src/nodes';
import { ConcurrentDeviceLimitError, InvalidExtensionTokenError, SessionService } from '../server/src/sessions';
import { toTestConfig } from '../server/src/config';
import { ownerHash, SAMPLE_NODE, tmpDir } from './helpers';

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
    ownerHash: ownerHash(),
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
    const enrollment = sessions.issueExtensionToken(session.id);
    const first = sessions.heartbeatByExtensionToken(enrollment, '127.0.0.1');
    expect(first.enrolled).toBe(true);
    expect(first.rotatedToken).toBeTruthy();
    now += 20_000;
    expect(sessions.isActive(session, now)).toBe(true);
    const second = sessions.heartbeatByExtensionToken(first.rotatedToken!, '127.0.0.1');
    expect(second.expiresAt).toBe(session.expiresAt);
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

  it('revokes a session and invalidates every token', () => {
    const { sessions } = makeServices(() => Date.now());
    const session = sessions.create(createInput('device-eeeeeeee'));
    const enrollment = sessions.issueExtensionToken(session.id);
    const first = sessions.heartbeatByExtensionToken(enrollment, '127.0.0.1');
    sessions.revoke(session.id, 'admin_revoked');
    expect(session.revoked).toBe(true);
    expect(() => sessions.heartbeatByExtensionToken(first.rotatedToken!, '127.0.0.1')).toThrow(InvalidExtensionTokenError);
  });

  it('consumes the CRX enrollment token exactly once', () => {
    const { sessions } = makeServices(() => Date.now());
    const session = sessions.create(createInput('device-ffffffff'));
    const enrollment = sessions.issueExtensionToken(session.id);

    const first = sessions.heartbeatByExtensionToken(enrollment, '127.0.0.1');
    expect(first.enrolled).toBe(true);
    expect(first.rotatedToken).toBeTruthy();
    expect(first.rotatedToken).not.toBe(enrollment);

    // Replaying the artifact token from the CRX must fail forever.
    expect(() => sessions.heartbeatByExtensionToken(enrollment, '127.0.0.1')).toThrow(InvalidExtensionTokenError);

    // Only the rotated token can continue the session.
    const second = sessions.heartbeatByExtensionToken(first.rotatedToken!, '127.0.0.1');
    expect(second.rotatedToken).toBeTruthy();
  });

  it('rejects an enrollment token after its short TTL', () => {
    let now = 1_700_000_000_000;
    const { sessions } = makeServices(() => now, { enrollmentTtlSeconds: 60 });
    const session = sessions.create(createInput('device-gggggggg'));
    const enrollment = sessions.issueExtensionToken(session.id);
    now += 61_000;
    expect(() => sessions.heartbeatByExtensionToken(enrollment, '127.0.0.1')).toThrow(InvalidExtensionTokenError);
  });

  it('accepts the previous access token only during the rotation grace window', () => {
    let now = 1_700_000_000_000;
    const { sessions } = makeServices(() => now, { sessionTtlSeconds: 600, sessionIdleSeconds: 120, tokenGraceSeconds: 30 });
    const session = sessions.create(createInput('device-hhhhhhhh'));
    const enrollment = sessions.issueExtensionToken(session.id);
    const first = sessions.heartbeatByExtensionToken(enrollment, '127.0.0.1');
    const accessA = first.rotatedToken!;
    const second = sessions.heartbeatByExtensionToken(accessA, '127.0.0.1');
    const accessB = second.rotatedToken!;

    // Replaying A immediately is accepted because it is still the previous token.
    const recovered = sessions.heartbeatByExtensionToken(accessA, '127.0.0.1');
    expect(recovered.rotatedToken).toBeTruthy();

    // After the grace window B is no longer previous (A is), so B is stale.
    now += 31_000;
    expect(() => sessions.heartbeatByExtensionToken(accessB, '127.0.0.1')).toThrow(InvalidExtensionTokenError);
  });

  it('invalidates a previously downloaded enrollment token when a new CRX is issued', () => {
    const { sessions } = makeServices(() => Date.now());
    const session = sessions.create(createInput('device-iiiiiiii'));
    const oldEnrollment = sessions.issueExtensionToken(session.id);
    const newEnrollment = sessions.issueExtensionToken(session.id);
    expect(newEnrollment).not.toBe(oldEnrollment);
    expect(() => sessions.heartbeatByExtensionToken(oldEnrollment, '127.0.0.1')).toThrow(InvalidExtensionTokenError);
    const first = sessions.heartbeatByExtensionToken(newEnrollment, '127.0.0.1');
    expect(first.enrolled).toBe(true);
  });
});
