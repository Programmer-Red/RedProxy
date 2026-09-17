import fs from 'node:fs';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { currentTotp, loginAdminAgent, loginUserAgent, testApp } from './helpers';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('user portal TOTP login', () => {
  it('rejects a wrong TOTP code and accepts a correct one', async () => {
    const { userApp, config } = testApp();
    tempDirs.push(config.dataDir);

    const wrong = await request(userApp).post('/api/auth/totp').send({ token: '000000' });
    expect(wrong.status).toBe(401);
    expect(wrong.body.error).toBe('invalid_totp');

    const good = await request(userApp).post('/api/auth/totp').send({ token: currentTotp() });
    expect(good.status).toBe(200);
    expect(good.body.authenticated).toBe(true);
    expect(String(good.headers['set-cookie']?.[0] ?? '')).toContain('HttpOnly');
  });

  it('never asks the end user for an admin password, even in totp_password mode', async () => {
    const { userApp, adminApp, config } = testApp();
    tempDirs.push(config.dataDir);

    // Configure the admin portal to require a password.
    const admin = await loginAdminAgent(adminApp);
    await admin.post('/api/settings/password').send({ password: 'correct-horse-battery' });
    await admin.patch('/api/settings').send({ authMode: 'totp_password' });

    // The user portal still only needs TOTP.
    const user = await request(userApp).post('/api/auth/totp').send({ token: currentTotp() });
    expect(user.status).toBe(200);
  });

  it('logout removes the user session', async () => {
    const { userApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginUserAgent(userApp);
    expect((await agent.get('/api/me')).status).toBe(200);
    await agent.post('/api/auth/logout').send({});
    expect((await agent.get('/api/me')).status).toBe(401);
  });

  it('does not let a user session access the admin portal', async () => {
    const { userApp, adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const login = await request(userApp).post('/api/auth/totp').send({ token: currentTotp() });
    const userCookie = String(login.headers['set-cookie']?.[0] ?? '').split(';')[0] ?? '';
    expect(userCookie).toContain('redproxy_user=');
    // Reusing the user cookie against the admin site must be rejected.
    const response = await request(adminApp).get('/api/nodes').set('Cookie', userCookie);
    expect(response.status).toBe(401);
  });
});

describe('login rate limiting and bans', () => {
  it('bans the client IP after repeated failures', async () => {
    const nowValue = 1_700_000_000_000;
    const { userApp, config } = testApp({ now: () => nowValue, loginMaxAttempts: 3, loginBanSeconds: 600 });
    tempDirs.push(config.dataDir);

    for (let i = 0; i < 3; i += 1) {
      const response = await request(userApp).post('/api/auth/totp').send({ token: '000000' });
      expect(response.status).toBe(401);
    }

    const blocked = await request(userApp).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) });
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toBe('ip_banned');
    expect(blocked.headers['retry-after']).toBeDefined();
  });

  it('can list and unban a banned IP from the admin portal', async () => {
    const nowValue = 1_700_000_000_000;
    const { userApp, adminApp, config } = testApp({ now: () => nowValue, loginMaxAttempts: 2, loginBanSeconds: 600 });
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp, { timestamp: nowValue });

    await request(userApp).post('/api/auth/totp').send({ token: '000000' });
    await request(userApp).post('/api/auth/totp').send({ token: '000000' });
    const blocked = await request(userApp).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) });
    expect(blocked.status).toBe(429);

    const banList = await admin.get('/api/login-bans');
    expect(banList.status).toBe(200);
    expect(banList.body.bans.length).toBe(1);
    const ip = banList.body.bans[0].ip as string;

    const unban = await admin.delete(`/api/login-bans/${encodeURIComponent(ip)}`);
    expect(unban.status).toBe(200);
    expect((await admin.get('/api/login-bans')).body.bans.length).toBe(0);

    const allowedAgain = await request(userApp).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) });
    expect(allowedAgain.status).toBe(200);
  });
});

describe('admin portal authentication', () => {
  it('supports TOTP + password authentication mode', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp);

    const setPassword = await admin.post('/api/settings/password').send({ password: 'correct-horse-battery' });
    expect(setPassword.status).toBe(200);

    const switchMode = await admin.patch('/api/settings').send({ authMode: 'totp_password' });
    expect(switchMode.status).toBe(200);
    expect(switchMode.body.authMode).toBe('totp_password');

    const mode = await request(adminApp).get('/api/auth/mode');
    expect(mode.body.authMode).toBe('totp_password');
    expect(mode.body.passwordRequired).toBe(true);

    const missingPassword = await request(adminApp).post('/api/auth/totp').send({ token: currentTotp() });
    expect(missingPassword.status).toBe(401);

    const wrongPassword = await request(adminApp).post('/api/auth/totp').send({ token: currentTotp(), password: 'nope-nope-nope' });
    expect(wrongPassword.status).toBe(401);

    const good = await request(adminApp).post('/api/auth/totp').send({ token: currentTotp(), password: 'correct-horse-battery' });
    expect(good.status).toBe(200);
  });

  it('refuses to switch to password mode before a password exists', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp);
    const response = await admin.patch('/api/settings').send({ authMode: 'totp_password' });
    expect(response.status).toBe(409);
    expect(response.body.error).toBe('password_required');
  });

  it('returns a QR code for TOTP enrolment', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp);
    const settings = await admin.get('/api/settings');
    expect(settings.status).toBe(200);
    expect(settings.body.qrDataUrl).toMatch(/^data:image\/png;base64,/);
    expect(settings.body.otpauthUri).toContain('otpauth://totp/');

    const regenerated = await admin.post('/api/settings/totp/regenerate').send({ currentTotp: currentTotp() });
    expect(regenerated.status).toBe(200);
    expect(regenerated.body.totpSecretBase32).not.toBe(settings.body.totpSecretBase32);
  });
});
