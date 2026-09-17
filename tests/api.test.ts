import fs from 'node:fs';
import JSZip from 'jszip';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { loginAdminAgent, loginUserAgent, SAMPLE_NODE, testApp } from './helpers';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

function binaryParser(res: request.Response, callback: (error: Error | null, body: Buffer) => void) {
  const chunks: Buffer[] = [];
  res.on('data', chunk => chunks.push(Buffer.from(chunk)));
  res.on('end', () => callback(null, Buffer.concat(chunks)));
}

async function extractExtensionToken(zipBody: Buffer): Promise<string> {
  const zip = await JSZip.loadAsync(zipBody);
  const background = await zip.file('background.js')!.async('string');
  const match = /var CONFIG = (\{[\s\S]*?\});/.exec(background);
  if (!match) throw new Error('config not found in background.js');
  return JSON.parse(match[1]!).extensionToken as string;
}

describe('site separation', () => {
  it('serves the user portal on the user site and the admin portal on the admin site', async () => {
    const { userApp, adminApp, config } = testApp();
    tempDirs.push(config.dataDir);

    const userIndex = await request(userApp).get('/');
    expect(userIndex.status).toBe(200);
    expect(userIndex.text).toContain('临时会话');
    expect(userIndex.text).not.toContain('节点管理');

    const adminIndex = await request(adminApp).get('/');
    expect(adminIndex.status).toBe(200);
    expect(adminIndex.text).toContain('管理后台');
    expect(adminIndex.text).toContain('导入导出');
  });

  it('keeps user and admin sessions independent', async () => {
    const { userApp, adminApp, config, services } = testApp();
    tempDirs.push(config.dataDir);
    await loginUserAgent(userApp);
    expect(services.auth.sessionCount()).toBe(1);
    await loginAdminAgent(adminApp);
    expect(services.auth.sessionCount()).toBe(2);

    // An anonymous request to either site's admin API fails.
    expect((await request(adminApp).get('/api/nodes')).status).toBe(401);
    expect((await request(userApp).get('/api/nodes')).status).toBe(401);
  });
});

describe('HTTP API integration', () => {
  it('lets an admin create a node and a user download a one-time extension', async () => {
    const { userApp, adminApp, config } = testApp();
    tempDirs.push(config.dataDir);

    const admin = await loginAdminAgent(adminApp);
    const createdNode = await admin.post('/api/nodes').send(SAMPLE_NODE);
    expect(createdNode.status).toBe(201);
    expect(createdNode.body.node.hasAuth).toBe(false);

    const user = await loginUserAgent(userApp);
    const nodeList = await user.get('/api/nodes');
    expect(nodeList.status).toBe(200);
    expect(nodeList.body.nodes.length).toBe(1);
    // Users must never see long-term credentials.
    expect(nodeList.body.nodes[0].username).toBeUndefined();
    expect(nodeList.body.nodes[0].password).toBeUndefined();

    const sessionResponse = await user.post('/api/session').send({ deviceId: 'device-api-test-1', nodeId: SAMPLE_NODE.id, ttlSeconds: 300 });
    expect(sessionResponse.status).toBe(201);
    expect(sessionResponse.body.session.state).toBe('pending');

    const zipResponse = await user.get('/api/session/extension.zip').buffer(true).parse(binaryParser);
    expect(zipResponse.status).toBe(200);
    const enrollmentToken = await extractExtensionToken(zipResponse.body);

    const firstHeartbeat = await request(userApp)
      .post('/api/extension/heartbeat')
      .set('Authorization', `Bearer ${enrollmentToken}`)
      .send({});
    expect(firstHeartbeat.status).toBe(200);
    expect(firstHeartbeat.body.rotated).toBe(true);
    const rotatedToken = firstHeartbeat.body.token as string;

    const replay = await request(userApp).post('/api/extension/heartbeat').set('Authorization', `Bearer ${enrollmentToken}`).send({});
    expect(replay.status).toBe(401);

    const adminSessions = await admin.get('/api/sessions');
    expect(adminSessions.body.sessions[0].enrolled).toBe(true);

    const revoked = await admin.delete(`/api/sessions/${sessionResponse.body.session.id}`);
    expect(revoked.body.revoked).toBe(true);
    const afterRevoke = await request(userApp).post('/api/extension/heartbeat').set('Authorization', `Bearer ${rotatedToken}`).send({});
    expect(afterRevoke.status).toBe(401);
  });

  it('reports 404 for a revoked session download so the client can recreate it', async () => {
    const { userApp, adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp);
    await admin.post('/api/nodes').send(SAMPLE_NODE);

    const user = await loginUserAgent(userApp);
    await user.post('/api/session').send({ deviceId: 'device-download-retry', nodeId: SAMPLE_NODE.id, ttlSeconds: 300 });

    // Simulate the pagehide beacon revoking the session before the download.
    await user.post('/api/session/revoke').send({});
    const missing = await user.get('/api/session/extension.zip');
    expect(missing.status).toBe(404);
    expect(missing.body.error).toBe('session_not_found');

    // The client recreates the session, then the download succeeds.
    const recreated = await user.post('/api/session').send({ deviceId: 'device-download-retry', nodeId: SAMPLE_NODE.id, ttlSeconds: 300 });
    expect(recreated.status).toBe(201);
    const zip = await user.get('/api/session/extension.zip').buffer(true).parse(binaryParser);
    expect(zip.status).toBe(200);
    expect(Buffer.isBuffer(zip.body)).toBe(true);
    expect(zip.body.length).toBeGreaterThan(500);
  });

  it('exposes the shipped default credentials only before they are changed', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);

    const before = await request(adminApp).get('/api/bootstrap');
    expect(before.body.needsSetup).toBe(true);
    expect(before.body.defaults).toEqual({ username: 'admin', password: 'redproxy' });

    const admin = await loginAdminAgent(adminApp);
    await admin.post('/api/settings/password').send({ password: 'a-much-better-password' });

    const after = await request(adminApp).get('/api/bootstrap');
    expect(after.body.needsSetup).toBe(false);
    expect(after.body.defaults).toBeNull();
  });

  it('validates node input and rejects unsupported protocols and ports', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp);

    expect((await admin.post('/api/nodes').send({ ...SAMPLE_NODE, scheme: 'vmess' })).status).toBe(400);
    expect((await admin.post('/api/nodes').send({ ...SAMPLE_NODE, port: 70000 })).status).toBe(400);
    expect((await admin.post('/api/nodes').send({ ...SAMPLE_NODE, scheme: 'socks4' })).status).toBe(201);
  });

  it('imports nodes from JSON and share links and exports them again', async () => {
    const { adminApp, config } = testApp();
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp);

    const importResponse = await admin.post('/api/nodes/import').send({
      text: JSON.stringify([SAMPLE_NODE]) + '\n' + 'vless://11111111-1111-1111-1111-111111111111@remote.example.com:443?encryption=none&security=tls&sni=remote.example.com&type=ws&path=%2Fws#Imported%20VLESS',
    });
    expect(importResponse.status).toBe(200);
    expect(importResponse.body.importedCount).toBe(2);

    const exportResponse = await admin.get('/api/nodes/export?secrets=true');
    expect(exportResponse.body.nodes.length).toBe(2);

    const links = await admin.get('/api/nodes/export/links');
    expect(links.body.links.some((link: string) => link.startsWith('vless://'))).toBe(true);

    const xrayNode = importResponse.body.imported.find((node: { kind: string }) => node.kind === 'xray');
    const xrayConfig = await admin.get(`/api/xray/config/${xrayNode.id}`);
    expect(xrayConfig.status).toBe(200);
    expect(xrayConfig.body.inbounds[0].port).toBe(xrayNode.localPort);
    expect(xrayConfig.body.outbounds[0].protocol).toBe('vless');
    expect(xrayConfig.body.outbounds[0].settings.vnext[0].address).toBe('remote.example.com');
  });

  it('enforces the concurrent device limit across user sessions', async () => {
    const { userApp, adminApp, config } = testApp({ maxConcurrentDevices: 1 });
    tempDirs.push(config.dataDir);
    const admin = await loginAdminAgent(adminApp);
    await admin.post('/api/nodes').send(SAMPLE_NODE);

    const user = await loginUserAgent(userApp);
    const first = await user.post('/api/session').send({ deviceId: 'device-limit-1', nodeId: SAMPLE_NODE.id, ttlSeconds: 300 });
    expect(first.status).toBe(201);
    const second = await user.post('/api/session').send({ deviceId: 'device-limit-2', nodeId: SAMPLE_NODE.id, ttlSeconds: 300 });
    expect(second.status).toBe(429);
    expect(second.body.error).toBe('concurrent_device_limit');
  });
});
