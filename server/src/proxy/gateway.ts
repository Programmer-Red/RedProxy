import net from 'node:net';
import type { Server } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import type { AppServices } from '../services';
import type { NodeRecord, ProxyScheme } from '../types';
import { socksHandshake, type UpstreamTarget } from './socks';

export interface ProxyAuthResult {
  sessionId: string;
  nodeId: string;
  username: string;
  password: string;
}

const PROXY_AUTH_HEADER = 'proxy-authorization';
const SUPPORTED_SCHEMES: ProxyScheme[] = ['http', 'https', 'socks4', 'socks5'];

/**
 * Extract the session token from a Proxy-Authorization header.
 * Chrome sends `Proxy-Authorization: Basic base64(token:)` when the proxy
 * address includes a username, so the extension bakes the one-time token in as
 * the proxy username.
 */
export function parseProxyAuthorization(header: string | undefined): ProxyAuthResult | null {
  if (!header) return null;
  const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header.trim());
  if (!match) return null;
  let decoded: string;
  try {
    decoded = Buffer.from(match[1]!, 'base64').toString('utf8');
  } catch {
    return null;
  }
  const separator = decoded.indexOf(':');
  const username = separator >= 0 ? decoded.slice(0, separator) : decoded;
  const password = separator >= 0 ? decoded.slice(separator + 1) : '';
  if (!username) return null;
  return { sessionId: '', nodeId: '', username, password };
}

export class ProxyGateway {
  constructor(
    private readonly services: AppServices,
    private readonly log: (...args: unknown[]) => void = () => undefined,
  ) {}

  /**
   * Authenticate a CONNECT / absolute-URI request using the one-time token and
   * return the node the session is allowed to reach. Returns null when the
   * request should be answered with 407.
   */
  authenticate(header: string | undefined, realm: string): { ok: true; node: NodeRecord; sessionId: string } | { ok: false; challenge: string } {
    const challenge = `Basic realm="${realm}", charset="UTF-8"`;
    const parsed = parseProxyAuthorization(header);
    if (!parsed) return { ok: false, challenge };
    const session = this.services.sessions.findActiveByAccessToken(parsed.username);
    if (!session) return { ok: false, challenge };
    const node = this.services.nodes.get(session.nodeId);
    if (!node || !node.enabled) return { ok: false, challenge };
    return { ok: true, node, sessionId: session.id };
  }

  /** Open a TCP connection to the node that this session is bound to. */
  async connectToNode(node: NodeRecord, timeoutMs: number): Promise<net.Socket> {
    const endpoint = this.nodeEndpoint(node);
    const socket = await this.connect(endpoint.host, endpoint.port, timeoutMs);
    if (endpoint.scheme === 'socks4' || endpoint.scheme === 'socks5') {
      await socksHandshake(socket, endpoint.scheme, { host: '0.0.0.0', port: 0 }, { username: null, password: null });
    }
    return socket;
  }

  /** The address the server itself dials. For Xray nodes this is the local inbound. */
  nodeEndpoint(node: NodeRecord): { scheme: ProxyScheme; host: string; port: number } {
    if (node.kind === 'xray') {
      const scheme = node.localScheme && SUPPORTED_SCHEMES.includes(node.localScheme) ? node.localScheme : 'socks5';
      return { scheme, host: node.localHost || '127.0.0.1', port: node.localPort || 10808 };
    }
    return { scheme: node.scheme, host: node.host, port: node.port };
  }

  connect(host: string, port: number, timeoutMs: number): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const socket = net.connect({ host, port });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`connect timeout to ${host}:${port}`));
      }, timeoutMs);
      socket.once('connect', () => {
        clearTimeout(timer);
        socket.setNoDelay(true);
        resolve(socket);
      });
      socket.once('error', error => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  /**
   * Handle a plain HTTP request (absolute-form URI) through the node. For
   * socks/http nodes we simply relay the raw bytes to the node, which is
   * itself a proxy and will understand the absolute-form request.
   */
  handleHttpRequest(req: IncomingMessage, res: ServerResponse, node: NodeRecord): void {
    const endpoint = this.nodeEndpoint(node);
    if (endpoint.scheme !== 'http' && endpoint.scheme !== 'https' && endpoint.scheme !== 'socks4' && endpoint.scheme !== 'socks5') {
      res.writeHead(502).end('unsupported node scheme');
      return;
    }
    // Relaying absolute-form HTTP to an HTTP proxy, or tunnelling through SOCKS,
    // both work by piping the raw request bytes.
    this.pipeHttpToNode(req, res, node).catch(error => {
      this.log('proxy http relay failed', error instanceof Error ? error.message : error);
      if (!res.headersSent) res.writeHead(502).end('proxy relay failed');
      else res.destroy();
    });
  }

  private async pipeHttpToNode(req: IncomingMessage, res: ServerResponse, node: NodeRecord): Promise<void> {
    const socket = await this.connectToNode(node, this.services.config.proxyConnectTimeoutMs);
    // Forward the original request (headers + body) to the node proxy.
    const lines: string[] = [`${req.method} ${req.url} HTTP/1.1`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i]!;
      const value = req.rawHeaders[i + 1] ?? '';
      if (name.toLowerCase() === PROXY_AUTH_HEADER) continue;
      lines.push(`${name}: ${value}`);
    }
    lines.push('Proxy-Connection: keep-alive', '', '');
    socket.write(lines.join('\r\n'));
    req.pipe(socket);
    socket.pipe(res);
    const close = (): void => {
      socket.destroy();
    };
    res.on('close', close);
    req.on('error', close);
    socket.on('error', () => {
      if (!res.headersSent) res.writeHead(502).end('upstream error');
      else res.destroy();
    });
  }

  /**
   * Handle a CONNECT request by opening a TCP tunnel to the node and then
   * performing the node's own CONNECT/SOCKS handshake toward the target.
   */
  handleConnect(req: IncomingMessage, clientSocket: Duplex, head: Buffer, node: NodeRecord): void {
    this.establishTunnel(node, req.url || '', clientSocket, head).catch(error => {
      this.log('proxy CONNECT failed', error instanceof Error ? error.message : error);
      clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    });
  }

  private async establishTunnel(node: NodeRecord, target: string, clientSocket: Duplex, head: Buffer): Promise<void> {
    const separator = target.lastIndexOf(':');
    if (separator <= 0) throw new Error(`invalid CONNECT target: ${target}`);
    const host = target.slice(0, separator).replace(/^\[|\]$/g, '');
    const port = Number.parseInt(target.slice(separator + 1), 10);
    if (!Number.isFinite(port) || port <= 0 || port > 65535) throw new Error(`invalid CONNECT port: ${target}`);

    const endpoint = this.nodeEndpoint(node);
    const upstream = await this.connect(endpoint.host, endpoint.port, this.services.config.proxyConnectTimeoutMs);
    const targetInfo: UpstreamTarget = { host, port };

    let earlyBytes: Buffer = Buffer.alloc(0);
    if (endpoint.scheme === 'socks5' || endpoint.scheme === 'socks4') {
      await socksHandshake(upstream, endpoint.scheme, targetInfo, { username: null, password: null });
    } else {
      // HTTP / HTTPS node: ask it to CONNECT to the final target.
      const authority = `${host}:${port}`;
      upstream.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\nProxy-Connection: keep-alive\r\n\r\n`);
      earlyBytes = await waitForConnectReply(upstream);
    }

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length > 0) upstream.write(head);
    // The target may already have sent data (e.g. a server banner) before the
    // tunnel was fully set up; forward it instead of dropping it.
    if (earlyBytes.length > 0) clientSocket.write(earlyBytes);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
    const cleanup = (): void => {
      upstream.destroy();
      clientSocket.destroy();
    };
    clientSocket.on('error', cleanup);
    clientSocket.on('close', cleanup);
    upstream.on('error', cleanup);
    upstream.on('close', cleanup);
  }
}

function waitForConnectReply(socket: net.Socket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      const statusLine = buffer.subarray(0, buffer.indexOf('\r\n')).toString('utf8');
      const match = /^HTTP\/\d\.\d\s+(\d{3})/.exec(statusLine);
      cleanup();
      const status = match ? Number.parseInt(match[1]!, 10) : 0;
      if (status >= 200 && status < 300) {
        // Any bytes after the header are already tunnel payload.
        resolve(buffer.subarray(end + 4));
      } else {
        reject(new Error(`node proxy CONNECT failed: ${statusLine}`));
      }
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const cleanup = (): void => {
      socket.off('data', onData);
      socket.off('error', onError);
    };
    socket.on('data', onData);
    socket.on('error', onError);
  });
}

/**
 * Attach the CONNECT tunnel handler to an HTTP/HTTPS server. Chrome sends
 * CONNECT at the socket level, so it never reaches Express.
 */
export function attachProxyConnect(server: Server, gateway: ProxyGateway, realm: string): void {
  server.on('connect', (req, clientSocket, head) => {
    const decision = gateway.authenticate(req.headers['proxy-authorization'], realm);
    if (!decision.ok) {
      clientSocket.write(
        `HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: ${decision.challenge}\r\nConnection: close\r\n\r\n`,
      );
      clientSocket.destroy();
      return;
    }
    gateway.handleConnect(req, clientSocket, head, decision.node);
  });
}
