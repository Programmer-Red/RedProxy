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

describe('HTTP API integration', () => {
  it('protects admin APIs and supports the full session download flow', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    const anonymous = await request(app).get('/api/admin/nodes');
    expect(anonymous.status).toBe(401);

    const agent = await loginAgent(app);

    const createdNode = await agent.post('/api/admin/nodes').send(SAMPLE_NODE);
    expect(createdNode.status).toBe(201);
    expect(createdNode.body.node.password).toBeUndefined();
    expect(createdNode.body.node.hasAuth).toBe(false);

    const sessionResponse = await agent.post('/api/session').send({
      deviceId: 'device-api-test-1',
      nodeId: SAMPLE_NODE.id,
      ttlSeconds: 300,
    });
    expect(sessionResponse.status).toBe(201);
    expect(sessionResponse.body.session.state).toBe('active');

    const crxResponse = await agent.get('/api/session/extension.crx').buffer(true).parse((res, callback) => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('end', () => callback(null, Buffer.concat(chunks)));
    });
    expect(crxResponse.status).toBe(200);
    expect(crxResponse.headers['content-type']).toContain('application/x-chrome-extension');
    expect(crxResponse.headers['cache-control']).toContain('no-store');
    expect(crxResponse.headers['content-disposition']).toContain('attachment');
    expect(Buffer.isBuffer(crxResponse.body)).toBe(true);
    expect(crxResponse.body.subarray(0, 4).toString('utf8')).toBe('Cr24');

    const zipResponse = await agent.get('/api/session/extension.zip').buffer(true).parse((res, callback) => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('end', () => callback(null, Buffer.concat(chunks)));
    });
    expect(zipResponse.status).toBe(200);
    const zip = await JSZip.loadAsync(zipResponse.body);
    const background = await zip.file('background.js')!.async('string');
    expect(background).toContain(SAMPLE_NODE.id);

    const revoked = await agent.post('/api/session/revoke').send({});
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);

    const afterRevoke = await agent.get('/api/session');
    expect(afterRevoke.body.session.state).not.toBe('active');
  });

  it('rejects invalid node protocols and ports', async () => {
    const { app, config } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app);

    const badScheme = await agent.post('/api/admin/nodes').send({ ...SAMPLE_NODE, scheme: 'vmess' });
    expect(badScheme.status).toBe(400);

    const badPort = await agent.post('/api/admin/nodes').send({ ...SAMPLE_NODE, port: 70000 });
    expect(badPort.status).toBe(400);
  });

  it('expires an extension token after the session is revoked', async () => {
    const { app, config, services } = testApp();
    tempDirs.push(config.dataDir);
    const agent = await loginAgent(app);
    await agent.post('/api/admin/nodes').send(SAMPLE_NODE);
    const sessionResponse = await agent.post('/api/session').send({
      deviceId: 'device-api-test-2',
      nodeId: SAMPLE_NODE.id,
      ttlSeconds: 300,
    });
    const session = services.sessions.get(sessionResponse.body.session.id)!;
    const token = services.sessions.issueExtensionToken(session.id);

    const firstHeartbeat = await request(app).post('/api/extension/heartbeat').set('Authorization', `Bearer ${token}`).send({});
    expect(firstHeartbeat.status).toBe(200);
    expect(firstHeartbeat.body.ok).toBe(true);

    await agent.delete(`/api/admin/sessions/${session.id}`);

    const revokedHeartbeat = await request(app).post('/api/extension/heartbeat').set('Authorization', `Bearer ${token}`).send({});
    expect(revokedHeartbeat.status).toBe(401);
    expect(revokedHeartbeat.body.error).toBe('invalid_extension_token');
  });
});
