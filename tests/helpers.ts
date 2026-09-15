import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as OTPAuth from 'otpauth';
import request from 'supertest';
import { createApp } from '../server/src/app';
import { toTestConfig } from '../server/src/config';
import type { AppConfig } from '../server/src/types';

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
  return { ...created, config };
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

export async function loginAgent(app: Parameters<typeof request.agent>[0], timestamp = Date.now()) {
  const agent = request.agent(app);
  const response = await agent.post('/api/auth/totp').send({ token: currentTotp(TEST_TOTP_SECRET, timestamp) });
  if (response.status !== 200) {
    throw new Error(`login failed in test: ${response.status} ${JSON.stringify(response.body)}`);
  }
  return agent;
}

export const SAMPLE_NODE = {
  id: 'tokyo-1',
  name: 'Tokyo',
  scheme: 'http' as const,
  host: '127.0.0.1',
  port: 10809,
  username: null,
  password: null,
  enabled: true,
};
