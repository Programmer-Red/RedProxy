import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { attachProxyConnect, parseProxyAuthorization, ProxyGateway } from '../server/src/proxy/gateway';
import { testApp, tmpDir } from './helpers';

const tempDirs: string[] = [];
const servers: Array<{ close: (cb?: () => void) => void }> = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

function listen(server: http.Server | net.Server): Promise<number> {
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve(typeof address === 'object' && address ? address.port : 0);
    });
    servers.push(server);
  });
}

/** A minimal upstream HTTP proxy that answers absolute-form GET requests. */
function fakeHttpProxy(body: string): http.Server {
  return http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain', 'X-Upstream': 'fake-proxy' });
    res.end(`${body} ${req.url}`);
  });
}

/** A minimal upstream HTTP proxy that tunnels CONNECT. */
function fakeConnectProxy(): net.Server {
  const server = net.createServer(client => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      client.off('data', onData);
      const line = buffer.subarray(0, buffer.indexOf('\r\n')).toString('utf8');
      const target = line.split(' ')[1] ?? '';
      const [host, port] = target.split(':');
      const upstream = net.connect({ host: host ?? '127.0.0.1', port: Number(port) || 80 });
      upstream.on('connect', () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        const rest = buffer.subarray(end + 4);
        if (rest.length > 0) upstream.write(rest);
        upstream.pipe(client);
        client.pipe(upstream);
      });
      upstream.on('error', () => client.destroy());
    };
    client.on('data', onData);
    client.on('error', () => client.destroy());
  });
  return server;
}

describe('proxy authorization parsing', () => {
  it('decodes Basic proxy credentials', () => {
    const header = `Basic ${Buffer.from('token-abc:').toString('base64')}`;
    expect(parseProxyAuthorization(header)).toMatchObject({ username: 'token-abc', password: '' });
    expect(parseProxyAuthorization(undefined)).toBeNull();
    expect(parseProxyAuthorization('Bearer nope')).toBeNull();
  });
});

describe('proxy gateway authentication', () => {
  it('rejects missing credentials with a Basic challenge', () => {
    const { services } = testApp();
    const gateway = new ProxyGateway(services);
    const result = gateway.authenticate(undefined, 'RedProxy');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.challenge).toContain('Basic realm="RedProxy"');
  });

  it('accepts an active session token and maps it to its node', () => {
    const { services } = testApp();
    const node = services.nodes.create({ name: 'N', kind: 'proxy', scheme: 'http', host: '127.0.0.1', port: 18080, enabled: true });
    const session = services.sessions.create({
      ownerHash: 'owner', deviceId: 'device-1', nodeId: node.id, ttlSeconds: 300, ip: '127.0.0.1', userAgent: 'test',
    });
    const token = services.sessions.issueExtensionToken(session.id);
    const gateway = new ProxyGateway(services);
    const result = gateway.authenticate(`Basic ${Buffer.from(`${token}:`).toString('base64')}`, 'RedProxy');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.node.id).toBe(node.id);
  });
});

describe('proxy gateway relaying', () => {
  it('relays absolute-form HTTP through the node proxy', async () => {
    const dataDir = tmpDir();
    tempDirs.push(dataDir);
    const app = testApp({ dataDir });
    const { userApp } = app;
    const upstreamPort = await listen(fakeHttpProxy('UPSTREAM'));
    const created = app.services.nodes.create({ name: 'N', kind: 'proxy', scheme: 'http', host: '127.0.0.1', port: upstreamPort, enabled: true });
    const session = app.services.sessions.create({
      ownerHash: 'owner', deviceId: 'device-1', nodeId: created.id, ttlSeconds: 300, ip: '127.0.0.1', userAgent: 'test',
    });
    const token = app.services.sessions.issueExtensionToken(session.id);

    const relay = http.createServer(userApp);
    const relayPort = await listen(relay);

    const body = await new Promise<string>((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: relayPort,
          method: 'GET',
          path: 'http://example.com/page',
          headers: { 'Proxy-Authorization': `Basic ${Buffer.from(`${token}:`).toString('base64')}` },
        },
        res => {
          const chunks: Buffer[] = [];
          res.on('data', chunk => chunks.push(Buffer.from(chunk)));
          res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        },
      );
      req.on('error', reject);
      req.end();
    });
    expect(body).toContain('UPSTREAM');
    expect(body).toContain('http://example.com/page');
  });

  it('tunnels CONNECT through the node proxy', async () => {
    const dataDir = tmpDir();
    tempDirs.push(dataDir);
    const upstreamPort = await listen(fakeConnectProxy());
    const echoPort = await listen(
      net.createServer(socket => {
        socket.write('HELLO');
        socket.end();
      }),
    );

    const app = testApp({ dataDir });
    const created = app.services.nodes.create({ name: 'N', kind: 'proxy', scheme: 'http', host: '127.0.0.1', port: upstreamPort, enabled: true });
    const session = app.services.sessions.create({
      ownerHash: 'owner', deviceId: 'device-2', nodeId: created.id, ttlSeconds: 300, ip: '127.0.0.1', userAgent: 'test',
    });
    const token = app.services.sessions.issueExtensionToken(session.id);

    const relay = http.createServer(app.userApp);
    attachProxyConnect(relay, app.gateway, app.proxyRealm);
    const relayPort = await listen(relay);

    const response = await new Promise<string>((resolve, reject) => {
      const socket = net.connect({ host: '127.0.0.1', port: relayPort });
      let buffer = '';
      socket.on('connect', () => {
        socket.write(
          `CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: 127.0.0.1:${echoPort}\r\n` +
            `Proxy-Authorization: Basic ${Buffer.from(`${token}:`).toString('base64')}\r\n\r\n`,
        );
      });
      socket.on('data', chunk => {
        buffer += chunk.toString('utf8');
        if (buffer.includes('HELLO')) {
          socket.destroy();
          resolve(buffer);
        }
      });
      socket.on('error', reject);
    });
    expect(response).toContain('200 Connection Established');
    expect(response).toContain('HELLO');
  });
});
