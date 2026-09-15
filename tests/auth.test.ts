import fs from 'node:fs';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { currentTotp, testApp } from './helpers';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('TOTP login', () => {
  it('rejects a wrong TOTP code and accepts a correct one', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);

    const wrong = await request(app).post('/api/auth/totp').send({ token: '000000' });
    expect(wrong.status).toBe(401);
    expect(wrong.body.error).toBe('invalid_totp');

    const good = await request(app).post('/api/auth/totp').send({ token: currentTotp() });
    expect(good.status).toBe(200);
    expect(good.body.authenticated).toBe(true);
    expect(String(good.headers['set-cookie']?.[0] ?? '')).toContain('HttpOnly');
  });

  it('rate limits repeated failures by IP', async () => {
    const nowValue = 1_700_000_000_000;
    const { app, config } = testApp({ now: () => nowValue, loginMaxAttempts: 3 });
    tempDirs.push(config.dataDir);

    for (let i = 0; i < 3; i += 1) {
      const response = await request(app).post('/api/auth/totp').send({ token: '000000' });
      expect(response.status).toBe(401);
    }

    const blocked = await request(app).post('/api/auth/totp').send({ token: '000000' });
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toBe('rate_limited');
    expect(blocked.headers['retry-after']).toBeDefined();
  });

  it('logout removes the session', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = request.agent(app);
    await agent.post('/api/auth/totp').send({ token: currentTotp() });
    expect((await agent.get('/api/me')).status).toBe(200);
    await agent.post('/api/auth/logout').send({});
    expect((await agent.get('/api/me')).status).toBe(401);
  });
});
