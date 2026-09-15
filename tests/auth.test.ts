import fs from 'node:fs';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { currentTotp, loginAgent, testApp } from './helpers';

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
    expect(wrong.body.error).toBe('invalid_credentials');

    const good = await request(app).post('/api/auth/totp').send({ token: currentTotp() });
    expect(good.status).toBe(200);
    expect(good.body.authenticated).toBe(true);
    expect(String(good.headers['set-cookie']?.[0] ?? '')).toContain('HttpOnly');
  });

  it('bans the client IP after repeated failures and exposes the ban in the admin API', async () => {
    const nowValue = 1_700_000_000_000;
    const { app, config } = testApp({ now: () => nowValue, loginMaxAttempts: 3, loginBanSeconds: 600 });
    tempDirs.push(config.dataDir);

    for (let i = 0; i < 3; i += 1) {
      const response = await request(app).post('/api/auth/totp').send({ token: '000000' });
      expect(response.status).toBe(401);
    }

    const blocked = await request(app).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) });
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toBe('ip_banned');
    expect(blocked.headers['retry-after']).toBeDefined();

    // Even the correct TOTP is refused while the IP is banned.
    const stillBlocked = await request(app).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) });
    expect(stillBlocked.status).toBe(429);
  });

  it('can list and unban a banned IP from the admin API', async () => {
    const nowValue = 1_700_000_000_000;
    const { app, config } = testApp({ now: () => nowValue, loginMaxAttempts: 2, loginBanSeconds: 600 });
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app, nowValue);

    await request(app).post('/api/auth/totp').send({ token: '000000' });
    await request(app).post('/api/auth/totp').send({ token: '000000' });
    const blocked = await request(app).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) });
    expect(blocked.status).toBe(429);

    const banList = await agent.get('/api/admin/login-bans');
    expect(banList.status).toBe(200);
    expect(banList.body.bans.length).toBe(1);
    const ip = banList.body.bans[0].ip as string;

    const unban = await agent.delete(`/api/admin/login-bans/${encodeURIComponent(ip)}`);
    expect(unban.status).toBe(200);
    expect((await agent.get('/api/admin/login-bans')).body.bans.length).toBe(0);

    const allowedAgain = await request(app).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) });
    expect(allowedAgain.status).toBe(200);
  });

  it('supports TOTP + password authentication mode', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app);

    const setPassword = await agent.post('/api/admin/settings/password').send({ password: 'correct-horse-battery' });
    expect(setPassword.status).toBe(200);

    const switchMode = await agent.patch('/api/admin/settings').send({ authMode: 'totp_password' });
    expect(switchMode.status).toBe(200);
    expect(switchMode.body.authMode).toBe('totp_password');

    const mode = await request(app).get('/api/auth/mode');
    expect(mode.body.authMode).toBe('totp_password');

    const missingPassword = await request(app).post('/api/auth/totp').send({ token: currentTotp() });
    expect(missingPassword.status).toBe(401);

    const wrongPassword = await request(app).post('/api/auth/totp').send({ token: currentTotp(), password: 'nope-nope-nope' });
    expect(wrongPassword.status).toBe(401);

    const good = await request(app).post('/api/auth/totp').send({ token: currentTotp(), password: 'correct-horse-battery' });
    expect(good.status).toBe(200);
  });

  it('refuses to switch to password mode before a password exists', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app);
    const response = await agent.patch('/api/admin/settings').send({ authMode: 'totp_password' });
    expect(response.status).toBe(409);
    expect(response.body.error).toBe('password_required');
  });

  it('logout removes the session', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app);
    expect((await agent.get('/api/me')).status).toBe(200);
    await agent.post('/api/auth/logout').send({});
    expect((await agent.get('/api/me')).status).toBe(401);
  });
});
