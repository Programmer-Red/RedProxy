import fs from 'node:fs';
import JSZip from 'jszip';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { loginAgent, SAMPLE_NODE, testApp } from './helpers';

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

describe('HTTP API integration', () => {
  it('protects admin APIs and supports the full one-time session download flow', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    expect((await request(app).get('/api/admin/nodes')).status).toBe(401);

    const agent = await loginAgent(app);
    const createdNode = await agent.post('/api/admin/nodes').send(SAMPLE_NODE);
    expect(createdNode.status).toBe(201);
    expect(createdNode.body.node.password).toBeUndefined();
    expect(createdNode.body.node.hasAuth).toBe(false);

    const sessionResponse = await agent.post('/api/session').send({ deviceId: 'device-api-test-1', nodeId: SAMPLE_NODE.id, ttlSeconds: 300 });
    expect(sessionResponse.status).toBe(201);
    expect(sessionResponse.body.session.state).toBe('pending');

    const crxResponse = await agent.get('/api/session/extension.crx').buffer(true).parse(binaryParser);
    expect(crxResponse.status).toBe(200);
    expect(crxResponse.headers['content-type']).toContain('application/x-chrome-extension');
    expect(crxResponse.headers['cache-control']).toContain('no-store');
    expect(crxResponse.headers['content-disposition']).toContain('attachment');
    expect(crxResponse.body.subarray(0, 4).toString('utf8')).toBe('Cr24');

    const zipResponse = await agent.get('/api/session/extension.zip').buffer(true).parse(binaryParser);
    expect(zipResponse.status).toBe(200);
    const enrollmentToken = await extractExtensionToken(zipResponse.body);

    const firstHeartbeat = await request(app)
      .post('/api/extension/heartbeat')
      .set('Authorization', `Bearer ${enrollmentToken}`)
      .send({});
    expect(firstHeartbeat.status).toBe(200);
    expect(firstHeartbeat.body.rotated).toBe(true);
    const rotatedToken = firstHeartbeat.body.token as string;
    expect(rotatedToken).toBeTruthy();
    expect(rotatedToken).not.toBe(enrollmentToken);

    // The artifact token cannot be replayed after enrollment.
    const replay = await request(app).post('/api/extension/heartbeat').set('Authorization', `Bearer ${enrollmentToken}`).send({});
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe('invalid_extension_token');

    const rotatedHeartbeat = await request(app).post('/api/extension/heartbeat').set('Authorization', `Bearer ${rotatedToken}`).send({});
    expect(rotatedHeartbeat.status).toBe(200);
    const newestToken = rotatedHeartbeat.body.token as string;

    const active = await agent.get('/api/session');
    expect(active.body.session.state).toBe('active');
    expect(active.body.session.enrolled).toBe(true);

    const revoked = await agent.post('/api/session/revoke').send({});
    expect(revoked.body.revoked).toBe(true);
    const afterRevoke = await request(app).post('/api/extension/heartbeat').set('Authorization', `Bearer ${newestToken}`).send({});
    expect(afterRevoke.status).toBe(401);
  });

  it('validates node input and rejects unsupported protocols and ports', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app);

    expect((await agent.post('/api/admin/nodes').send({ ...SAMPLE_NODE, scheme: 'vmess' })).status).toBe(400);
    expect((await agent.post('/api/admin/nodes').send({ ...SAMPLE_NODE, port: 70000 })).status).toBe(400);
    expect((await agent.post('/api/admin/nodes').send({ ...SAMPLE_NODE, scheme: 'socks4' })).status).toBe(201);
  });

  it('returns a QR code and supports auth settings management', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app);

    const settings = await agent.get('/api/admin/settings');
    expect(settings.status).toBe(200);
    expect(settings.body.qrDataUrl).toMatch(/^data:image\/png;base64,/);
    expect(settings.body.otpauthUri).toContain('otpauth://totp/');

    const regenerated = await agent.post('/api/admin/settings/totp/regenerate').send({ currentTotp: (await import('./helpers')).currentTotp() });
    expect(regenerated.status).toBe(200);
    expect(regenerated.body.qrDataUrl).toMatch(/^data:image\/png;base64,/);
  });

  it('imports nodes from JSON and share links and exports them again', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app);

    const importResponse = await agent.post('/api/admin/nodes/import').send({
      text: JSON.stringify([SAMPLE_NODE]) + '\n' + 'vless://11111111-1111-1111-1111-111111111111@remote.example.com:443?encryption=none&security=tls&sni=remote.example.com&type=ws&path=%2Fws#Imported%20VLESS',
    });
    expect(importResponse.status).toBe(200);
    expect(importResponse.body.importedCount).toBe(2);

    const exportResponse = await agent.get('/api/admin/nodes/export?secrets=true');
    expect(exportResponse.status).toBe(200);
    expect(exportResponse.body.nodes.length).toBe(2);

    const links = await agent.get('/api/admin/nodes/export/links');
    expect(links.body.links.some((link: string) => link.startsWith('vless://'))).toBe(true);

    const xrayNode = importResponse.body.imported.find((node: { kind: string }) => node.kind === 'xray');
    const xrayConfig = await agent.get(`/api/admin/xray/config/${xrayNode.id}`);
    expect(xrayConfig.status).toBe(200);
    expect(xrayConfig.body.inbounds[0].port).toBe(xrayNode.localPort);
    expect(xrayConfig.body.outbounds[0].protocol).toBe('vless');
    expect(xrayConfig.body.outbounds[0].settings.vnext[0].address).toBe('remote.example.com');
  });

  it('expires an extension token after the session is revoked by the admin', async () => {
    const { app, config, services } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app);
    await agent.post('/api/admin/nodes').send(SAMPLE_NODE);
    const sessionResponse = await agent.post('/api/session').send({ deviceId: 'device-api-test-2', nodeId: SAMPLE_NODE.id, ttlSeconds: 300 });
    const session = services.sessions.get(sessionResponse.body.session.id)!;
    const enrollment = services.sessions.issueExtensionToken(session.id);
    const first = services.sessions.heartbeatByExtensionToken(enrollment, '127.0.0.1');

    await agent.delete(`/api/admin/sessions/${session.id}`);
    const revokedHeartbeat = await request(app)
      .post('/api/extension/heartbeat')
      .set('Authorization', `Bearer ${first.rotatedToken}`)
      .send({});
    expect(revokedHeartbeat.status).toBe(401);
  });
});
