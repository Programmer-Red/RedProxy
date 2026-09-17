import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as OTPAuth from 'otpauth';
import request from 'supertest';
import type { Express } from 'express';
import { createApp } from '../server/src/app';
import { toTestConfig } from '../server/src/config';
import type { AppConfig, NodeRecord, ProxyScheme } from '../server/src/types';

export const TEST_TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

export function tmpDir(prefix = 'redproxy-test-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function testApp(overrides: Partial<AppConfig> & { now?: () => number } = {}) {
  const dataDir = (overrides.dataDir as string) || tmpDir();
  const config = toTestConfig({ dataDir, ...overrides });
  const created = createApp({
    config,
    totpSecret: TEST_TOTP_SECRET,
    publicDir: path.resolve(__dirname, '../public'),
    templateDir: path.resolve(__dirname, '../extension-template'),
    now: overrides.now,
  });
  return {
    userApp: created.userApp as Express,
    adminApp: created.adminApp as Express,
    services: created.services,
    config,
  };
}

export function currentTotp(secret = TEST_TOTP_SECRET, timestamp = Date.now()): string {
  const totp = new OTPAuth.TOTP({
    issuer: 'RedProxy',
    label: 'admin',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
  return totp.generate({ timestamp });
}

/** Log in to the end-user portal (TOTP only). */
export async function loginUserAgent(app: Express, timestamp = Date.now()) {
  const agent = request.agent(app);
  const response = await agent.post('/api/auth/totp').send({ token: currentTotp(TEST_TOTP_SECRET, timestamp) });
  if (response.status !== 200) {
    throw new Error(`user login failed in test: ${response.status} ${JSON.stringify(response.body)}`);
  }
  return agent;
}

/** Log in to the administrator portal. */
export async function loginAdminAgent(app: Express, options: { timestamp?: number; password?: string } = {}) {
  const agent = request.agent(app);
  const response = await agent
    .post('/api/auth/totp')
    .send({ token: currentTotp(TEST_TOTP_SECRET, options.timestamp ?? Date.now()), password: options.password });
  if (response.status !== 200) {
    throw new Error(`admin login failed in test: ${response.status} ${JSON.stringify(response.body)}`);
  }
  return agent;
}

/** Backwards-compatible alias for older tests that log into the admin portal. */
export const loginAgent = loginAdminAgent;

export function sampleNode(overrides: Partial<NodeRecord> = {}): NodeRecord {
  return {
    id: 'tokyo-1',
    name: 'Tokyo',
    kind: 'proxy',
    scheme: 'http' as ProxyScheme,
    host: '127.0.0.1',
    port: 10809,
    username: null,
    password: null,
    enabled: true,
    createdAt: Date.now(),
    ...overrides,
  };
}

export const SAMPLE_NODE = {
  id: 'tokyo-1',
  name: 'Tokyo',
  kind: 'proxy' as const,
  scheme: 'http' as const,
  host: '127.0.0.1',
  port: 10809,
  username: null,
  password: null,
  enabled: true,
};

export function ownerHash(value = 'owner'): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}
