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

describe('user portal authentication', () => {
  it('defaults to TOTP-only and rejects a wrong code', async () => {
    const { userApp, config } = testApp();
    tempDirs.push(config.dataDir);

    const mode = await request(userApp).get('/api/auth/mode');
    expect(mode.body.authMode).toBe('totp');
    expect(mode.body.totpRequired).toBe(true);
    expect(mode.body.passwordRequired).toBe(false);

    expect((await request(userApp).post('/api/auth/totp').send({ token: '000000' })).status).toBe(401);
    const good = await request(userApp).post('/api/auth/totp').send({ token: currentTotp() });
    expect(good.status).toBe(200);
    expect(String(good.headers['set-cookie']?.[0] ?? '')).toContain('redproxy_user=');
  });

  it('can be switched to password / totp_password and back by the admin', async () => {
    const { userApp, adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp);

    // password only
    await admin.patch('/api/settings').send({ userAuthMode: 'password' });
    let mode = await request(userApp).get('/api/auth/mode');
    expect(mode.body.authMode).toBe('password');
    expect((await request(userApp).post('/api/auth/totp').send({ password: 'redproxy' })).status).toBe(200);
    expect((await request(userApp).post('/api/auth/totp').send({ token: currentTotp() })).status).toBe(401);

    // totp + password
    await admin.patch('/api/settings').send({ userAuthMode: 'totp_password' });
    mode = await request(userApp).get('/api/auth/mode');
    expect(mode.body.authMode).toBe('totp_password');
    expect((await request(userApp).post('/api/auth/totp').send({ password: 'redproxy', token: currentTotp() })).status).toBe(200);

    // back to totp only
    await admin.patch('/api/settings').send({ userAuthMode: 'totp' });
    expect((await request(userApp).post('/api/auth/totp').send({ token: currentTotp() })).status).toBe(200);
  });

  it('logout removes the user session', async () => {
    const { userApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginUserAgent(userApp);
    expect((await agent.get('/api/me')).status).toBe(200);
    await agent.post('/api/auth/logout').send({});
    expect((await agent.get('/api/me')).status).toBe(401);
  });

  it('does not accept a user cookie on the admin portal', async () => {
    const { userApp, adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const login = await request(userApp).post('/api/auth/totp').send({ token: currentTotp() });
    const userCookie = String(login.headers['set-cookie']?.[0] ?? '').split(';')[0] ?? '';
    expect(userCookie).toContain('redproxy_user=');
    expect((await request(adminApp).get('/api/nodes').set('Cookie', userCookie)).status).toBe(401);
  });
});

describe('admin portal authentication', () => {
  it('starts in password mode with the shipped default account and forces a password change', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);

    const mode = await request(adminApp).get('/api/auth/mode');
    expect(mode.body.authMode).toBe('password');
    expect(mode.body.passwordRequired).toBe(true);
    expect(mode.body.totpRequired).toBe(false);

    const wrong = await request(adminApp).post('/api/auth/totp').send({ username: 'admin', password: 'nope' });
    expect(wrong.status).toBe(401);

    const good = await request(adminApp).post('/api/auth/totp').send({ username: 'admin', password: 'redproxy' });
    expect(good.status).toBe(200);
    expect(good.body.mustChangePassword).toBe(true);

    const agent = await loginAdminAgent(adminApp);
    const change = await agent.post('/api/settings/password').send({ password: 'a-much-better-password' });
    expect(change.status).toBe(200);
    expect(change.body.mustChangePassword).toBe(false);
  });

  it('supports switching the admin portal between password, totp and totp_password', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAdminAgent(adminApp);
    await agent.post('/api/settings/password').send({ password: 'a-much-better-password' });

    await agent.patch('/api/settings').send({ adminAuthMode: 'totp' });
    let mode = await request(adminApp).get('/api/auth/mode');
    expect(mode.body.authMode).toBe('totp');
    expect((await request(adminApp).post('/api/auth/totp').send({ token: currentTotp() })).status).toBe(200);

    await agent.patch('/api/settings').send({ adminAuthMode: 'totp_password' });
    mode = await request(adminApp).get('/api/auth/mode');
    expect(mode.body.authMode).toBe('totp_password');
    expect((await request(adminApp).post('/api/auth/totp').send({ token: currentTotp() })).status).toBe(401);
    expect((await request(adminApp).post('/api/auth/totp').send({ token: currentTotp(), password: 'a-much-better-password' })).status).toBe(200);

    await agent.patch('/api/settings').send({ adminAuthMode: 'password' });
    expect((await request(adminApp).post('/api/auth/totp').send({ username: 'admin', password: 'a-much-better-password' })).status).toBe(200);
  });

  it('refuses to enable password mode before a password exists', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAdminAgent(adminApp);
    // Remove the shipped default password first.
    await agent.delete('/api/settings/password');
    const response = await agent.patch('/api/settings').send({ adminAuthMode: 'password' });
    expect(response.status).toBe(409);
    expect(response.body.error).toBe('password_required');
  });

  it('returns a QR code for TOTP enrolment', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAdminAgent(adminApp);
    const settings = await agent.get('/api/settings');
    expect(settings.body.qrDataUrl).toMatch(/^data:image\/png;base64,/);
    expect(settings.body.otpauthUri).toContain('otpauth://totp/');

    const regenerated = await agent.post('/api/settings/totp/regenerate').send({ currentTotp: currentTotp() });
    expect(regenerated.status).toBe(200);
    expect(regenerated.body.totpSecretBase32).not.toBe(settings.body.totpSecretBase32);
  });
});

describe('login rate limiting and bans', () => {
  it('bans the client IP after repeated failures', async () => {
    const nowValue = 1_700_000_000_000;
    const { userApp, config } = testApp({ now: () => nowValue, loginMaxAttempts: 3, loginBanSeconds: 600 });
    tempDirs.push(config.dataDir);

    for (let i = 0; i < 3; i += 1) {
      expect((await request(userApp).post('/api/auth/totp').send({ token: '000000' })).status).toBe(401);
    }
    const blocked = await request(userApp).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) });
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toBe('ip_banned');
  });

  it('can list and unban a banned IP from the admin portal', async () => {
    const nowValue = 1_700_000_000_000;
    const { userApp, adminApp, config } = testApp({ now: () => nowValue, loginMaxAttempts: 2, loginBanSeconds: 600 });
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp);

    await request(userApp).post('/api/auth/totp').send({ token: '000000' });
    await request(userApp).post('/api/auth/totp').send({ token: '000000' });
    expect((await request(userApp).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) })).status).toBe(429);

    const banList = await admin.get('/api/login-bans');
    expect(banList.body.bans.length).toBe(1);
    const ip = banList.body.bans[0].ip as string;
    expect((await admin.delete(`/api/login-bans/${encodeURIComponent(ip)}`)).status).toBe(200);
    expect((await request(userApp).post('/api/auth/totp').send({ token: currentTotp(undefined, nowValue) })).status).toBe(200);
  });
});
