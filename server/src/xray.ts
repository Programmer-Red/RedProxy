import crypto from 'node:crypto';
import type { NodeRecord, ProxyScheme, XrayProtocol, XraySettings } from './types';

export interface ParsedNodeInput {
  name: string;
  kind: 'proxy' | 'xray';
  scheme: ProxyScheme;
  host: string;
  port: number;
  username: string | null;
  password: string | null;
  xray?: XraySettings;
  localScheme?: ProxyScheme;
  localHost?: string;
  localPort?: number;
  source?: string;
}

const XRAY_PROTOCOLS: XrayProtocol[] = ['vless', 'vmess', 'trojan', 'shadowsocks'];
const PROXY_SCHEMES: ProxyScheme[] = ['http', 'https', 'socks4', 'socks5'];

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function decodeBase64(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64').toString('utf8');
}

function parseUrl(rawLink: string): URL | null {
  try {
    return new URL(rawLink);
  } catch {
    return null;
  }
}

function nameFromHash(url: URL, fallback: string): string {
  const hash = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash;
  return safeDecode(hash).trim() || fallback;
}

function numberFrom(value: string | null | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 && parsed <= 65535 ? parsed : fallback;
}

function parseBool(value: string | null | undefined): boolean | null {
  if (value === null || value === undefined || value === '') return null;
  const normalized = value.toLowerCase();
  if (['1', 'true', 'yes'].includes(normalized)) return true;
  if (['0', 'false', 'no'].includes(normalized)) return false;
  return null;
}

function normalizeNetwork(value: string | null | undefined): XraySettings['network'] {
  if (!value) return 'tcp';
  const allowed = ['tcp', 'ws', 'grpc', 'http', 'kcp', 'quic', 'xhttp'];
  return allowed.includes(value) ? (value as XraySettings['network']) : 'tcp';
}

function normalizeSecurity(value: string | null | undefined): XraySettings['security'] {
  if (!value) return null;
  const allowed = ['none', 'tls', 'reality'];
  return allowed.includes(value) ? (value as XraySettings['security']) : null;
}

function defaultLocalPort(protocol: XrayProtocol): number {
  // Distinct default inbound ports so several imported nodes can run side by side.
  switch (protocol) {
    case 'vless':
      return 10801;
    case 'vmess':
      return 10802;
    case 'trojan':
      return 10803;
    case 'shadowsocks':
      return 10804;
    default:
      return 10808;
  }
}

function parseVless(link: string): ParsedNodeInput | null {
  const url = parseUrl(link);
  if (!url) return null;
  const id = safeDecode(url.username);
  if (!id) return null;
  const params = url.searchParams;
  const security = normalizeSecurity(params.get('security'));
  const xray: XraySettings = {
    protocol: 'vless',
    uuid: id,
    flow: params.get('flow'),
    network: normalizeNetwork(params.get('type')),
    security,
    sni: params.get('sni') || params.get('host') || null,
    fingerprint: params.get('fp'),
    publicKey: params.get('pbk'),
    shortId: params.get('sid'),
    spiderX: params.get('spx'),
    host: params.get('host'),
    path: params.get('path'),
    serviceName: params.get('serviceName'),
    allowInsecure: parseBool(params.get('allowInsecure')),
  };
  return {
    name: nameFromHash(url, `VLESS ${url.hostname}`),
    kind: 'xray',
    scheme: 'socks5',
    host: url.hostname,
    port: numberFrom(url.port, 443),
    username: null,
    password: null,
    xray,
    localScheme: 'socks5',
    localHost: '127.0.0.1',
    localPort: defaultLocalPort('vless'),
    source: link,
  };
}

function parseTrojan(link: string): ParsedNodeInput | null {
  const url = parseUrl(link);
  if (!url) return null;
  const password = safeDecode(url.username);
  if (!password) return null;
  const params = url.searchParams;
  const xray: XraySettings = {
    protocol: 'trojan',
    password,
    network: normalizeNetwork(params.get('type')),
    security: 'tls',
    sni: params.get('sni') || params.get('peer') || null,
    fingerprint: params.get('fp'),
    host: params.get('host'),
    path: params.get('path'),
    serviceName: params.get('serviceName'),
    allowInsecure: parseBool(params.get('allowInsecure')),
  };
  return {
    name: nameFromHash(url, `Trojan ${url.hostname}`),
    kind: 'xray',
    scheme: 'socks5',
    host: url.hostname,
    port: numberFrom(url.port, 443),
    username: null,
    password: null,
    xray,
    localScheme: 'socks5',
    localHost: '127.0.0.1',
    localPort: defaultLocalPort('trojan'),
    source: link,
  };
}

function parseShadowsocks(link: string): ParsedNodeInput | null {
  const url = parseUrl(link);
  if (!url) return null;
  const userInfo = safeDecode(url.username);
  let host = url.hostname;
  let port = numberFrom(url.port, 8388);
  let method = '';
  let password = '';

  if (userInfo.includes(':')) {
    const separator = userInfo.indexOf(':');
    method = userInfo.slice(0, separator);
    password = userInfo.slice(separator + 1);
  } else if (userInfo) {
    try {
      const decoded = decodeBase64(userInfo);
      const separator = decoded.indexOf(':');
      if (separator > 0) {
        method = decoded.slice(0, separator);
        password = decoded.slice(separator + 1);
      }
    } catch {
      return null;
    }
  } else {
    // Legacy format: ss://base64(method:password@host:port)
    const stripped = link.replace(/^ss:\/\//i, '').split('#')[0]?.split('?')[0] ?? '';
    try {
      const decoded = decodeBase64(stripped);
      const at = decoded.lastIndexOf('@');
      if (at < 0) return null;
      const credentials = decoded.slice(0, at);
      const endpoint = decoded.slice(at + 1);
      const separator = credentials.indexOf(':');
      if (separator < 0) return null;
      method = credentials.slice(0, separator);
      password = credentials.slice(separator + 1);
      const colon = endpoint.lastIndexOf(':');
      host = endpoint.slice(0, colon);
      port = numberFrom(endpoint.slice(colon + 1), 8388);
    } catch {
      return null;
    }
  }

  if (!method || !password || !host) return null;
  const xray: XraySettings = {
    protocol: 'shadowsocks',
    method,
    password,
    network: 'tcp',
  };
  return {
    name: nameFromHash(url, `Shadowsocks ${host}`),
    kind: 'xray',
    scheme: 'socks5',
    host,
    port,
    username: null,
    password: null,
    xray,
    localScheme: 'socks5',
    localHost: '127.0.0.1',
    localPort: defaultLocalPort('shadowsocks'),
    source: link,
  };
}

interface VmessJson {
  v?: string;
  ps?: string;
  add?: string;
  port?: string | number;
  id?: string;
  aid?: string | number;
  scy?: string;
  net?: string;
  type?: string;
  host?: string;
  path?: string;
  tls?: string;
  sni?: string;
  fp?: string;
}

function parseVmess(link: string): ParsedNodeInput | null {
  const payload = link.replace(/^vmess:\/\//i, '').split('#')[0] ?? '';
  let data: VmessJson;
  try {
    data = JSON.parse(decodeBase64(payload)) as VmessJson;
  } catch {
    return null;
  }
  if (!data.add || !data.id) return null;
  const security = data.tls === 'tls' ? 'tls' : data.tls === 'reality' ? 'reality' : null;
  const xray: XraySettings = {
    protocol: 'vmess',
    uuid: data.id,
    alterId: typeof data.aid === 'number' ? data.aid : Number.parseInt(String(data.aid ?? '0'), 10) || 0,
    network: normalizeNetwork(data.net),
    security,
    sni: data.sni || data.host || null,
    host: data.host,
    path: data.path,
    fingerprint: data.fp,
  };
  return {
    name: data.ps?.trim() || `VMess ${data.add}`,
    kind: 'xray',
    scheme: 'socks5',
    host: data.add,
    port: numberFrom(String(data.port ?? ''), 443),
    username: null,
    password: null,
    xray,
    localScheme: 'socks5',
    localHost: '127.0.0.1',
    localPort: defaultLocalPort('vmess'),
    source: link,
  };
}

function parseProxyUrl(link: string): ParsedNodeInput | null {
  const url = parseUrl(link);
  if (!url) return null;
  const schemeRaw = url.protocol.replace(':', '').toLowerCase();
  const schemeMap: Record<string, ProxyScheme> = {
    http: 'http',
    https: 'https',
    socks: 'socks5',
    socks5: 'socks5',
    socks4: 'socks4',
    socks4a: 'socks4',
  };
  const scheme = schemeMap[schemeRaw];
  if (!scheme) return null;
  const host = url.hostname;
  if (!host) return null;
  const port = numberFrom(url.port, scheme === 'https' ? 443 : 8080);
  return {
    name: nameFromHash(url, `${scheme.toUpperCase()} ${host}`),
    kind: 'proxy',
    scheme,
    host,
    port,
    username: url.username ? safeDecode(url.username) : null,
    password: url.password ? safeDecode(url.password) : null,
    source: link,
  };
}

export function parseShareLink(link: string): ParsedNodeInput | null {
  const trimmed = link.trim();
  if (!trimmed) return null;
  const lower = trimmed.toLowerCase();
  if (lower.startsWith('vless://')) return parseVless(trimmed);
  if (lower.startsWith('trojan://')) return parseTrojan(trimmed);
  if (lower.startsWith('ss://')) return parseShadowsocks(trimmed);
  if (lower.startsWith('vmess://')) return parseVmess(trimmed);
  if (/^(https?|socks4a?|socks5):\/\//.test(trimmed)) return parseProxyUrl(trimmed);
  return null;
}

export function buildXrayOutbound(node: NodeRecord): Record<string, unknown> {
  const xray = node.xray;
  if (!xray) throw new Error('node has no xray settings');
  const streamSettings = buildStreamSettings(xray);

  switch (xray.protocol) {
    case 'vless':
      return {
        tag: 'proxy',
        protocol: 'vless',
        settings: {
          vnext: [
            {
              address: node.host,
              port: node.port,
              users: [
                {
                  id: xray.uuid || crypto.randomUUID(),
                  encryption: 'none',
                  flow: xray.flow || '',
                },
              ],
            },
          ],
        },
        streamSettings,
      };
    case 'vmess':
      return {
        tag: 'proxy',
        protocol: 'vmess',
        settings: {
          vnext: [
            {
              address: node.host,
              port: node.port,
              users: [
                {
                  id: xray.uuid || crypto.randomUUID(),
                  alterId: xray.alterId ?? 0,
                  security: 'auto',
                },
              ],
            },
          ],
        },
        streamSettings,
      };
    case 'trojan':
      return {
        tag: 'proxy',
        protocol: 'trojan',
        settings: {
          servers: [{ address: node.host, port: node.port, password: xray.password || '' }],
        },
        streamSettings,
      };
    case 'shadowsocks':
      return {
        tag: 'proxy',
        protocol: 'shadowsocks',
        settings: {
          servers: [
            {
              address: node.host,
              port: node.port,
              method: xray.method || 'aes-256-gcm',
              password: xray.password || '',
            },
          ],
        },
        streamSettings,
      };
    default:
      throw new Error(`unsupported xray protocol: ${String(xray.protocol)}`);
  }
}

function buildStreamSettings(xray: XraySettings): Record<string, unknown> {
  const stream: Record<string, unknown> = {
    network: xray.network || 'tcp',
  };

  const network = xray.network || 'tcp';
  if (network === 'ws') {
    stream.wsSettings = {
      path: xray.path || '/',
      headers: xray.host ? { Host: xray.host } : {},
    };
  } else if (network === 'grpc') {
    stream.grpcSettings = { serviceName: xray.serviceName || '' };
  } else if (network === 'http' || network === 'xhttp') {
    stream.httpSettings = {
      host: xray.host ? [xray.host] : undefined,
      path: xray.path || '/',
    };
  }

  if (xray.security === 'tls') {
    stream.security = 'tls';
    stream.tlsSettings = {
      serverName: xray.sni || xray.host || nodeNameHostFallback(xray),
      fingerprint: xray.fingerprint || 'chrome',
      allowInsecure: Boolean(xray.allowInsecure),
    };
  } else if (xray.security === 'reality') {
    stream.security = 'reality';
    stream.realitySettings = {
      serverName: xray.sni || xray.host || nodeNameHostFallback(xray),
      fingerprint: xray.fingerprint || 'chrome',
      publicKey: xray.publicKey || '',
      shortId: xray.shortId || '',
      spiderX: xray.spiderX || '/',
    };
  }

  return stream;
}

function nodeNameHostFallback(xray: XraySettings): string {
  return xray.sni || xray.host || 'www.example.com';
}

export interface XrayConfigOptions {
  inboundPort?: number;
  inboundListen?: string;
  inboundProtocol?: 'socks' | 'http';
}

export function buildXrayConfig(node: NodeRecord, options: XrayConfigOptions = {}): Record<string, unknown> {
  const inboundPort = options.inboundPort ?? node.localPort ?? 10808;
  const inboundListen = options.inboundListen ?? node.localHost ?? '127.0.0.1';
  const protocol = options.inboundProtocol ?? (node.localScheme === 'http' || node.localScheme === 'https' ? 'http' : 'socks');

  return {
    log: { loglevel: 'warning' },
    inbounds: [
      {
        tag: 'redproxy-in',
        listen: inboundListen,
        port: inboundPort,
        protocol,
        settings:
          protocol === 'http'
            ? { udp: false, allowTransparent: false }
            : { udp: true, auth: 'noauth' },
        sniffing: { enabled: false },
      },
    ],
    outbounds: [
      buildXrayOutbound(node),
      { tag: 'direct', protocol: 'freedom', settings: {} },
      { tag: 'blocked', protocol: 'blackhole', settings: {} },
    ],
    routing: {
      domainStrategy: 'AsIs',
      rules: [],
    },
  };
}

function encodeBase64Json(value: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64').replace(/=+$/, '');
}

export function buildShareLink(node: NodeRecord): string | null {
  if (node.kind === 'proxy') {
    const credentials = node.username
      ? `${encodeURIComponent(node.username)}${node.password ? `:${encodeURIComponent(node.password)}` : ''}@`
      : '';
    const hash = node.name ? `#${encodeURIComponent(node.name)}` : '';
    return `${node.scheme}://${credentials}${node.host}:${node.port}${hash}`;
  }

  const xray = node.xray;
  if (!xray) return null;
  const params = new URLSearchParams();
  const hash = node.name ? `#${encodeURIComponent(node.name)}` : '';

  switch (xray.protocol) {
    case 'vless': {
      params.set('encryption', 'none');
      if (xray.flow) params.set('flow', xray.flow);
      if (xray.security) params.set('security', xray.security);
      if (xray.sni) params.set('sni', xray.sni);
      if (xray.fingerprint) params.set('fp', xray.fingerprint);
      if (xray.publicKey) params.set('pbk', xray.publicKey);
      if (xray.shortId) params.set('sid', xray.shortId);
      if (xray.spiderX) params.set('spx', xray.spiderX);
      if (xray.network) params.set('type', xray.network);
      if (xray.host) params.set('host', xray.host);
      if (xray.path) params.set('path', xray.path);
      if (xray.serviceName) params.set('serviceName', xray.serviceName);
      return `vless://${xray.uuid ?? ''}@${node.host}:${node.port}?${params.toString()}${hash}`;
    }
    case 'trojan': {
      if (xray.security) params.set('security', xray.security);
      if (xray.sni) params.set('sni', xray.sni);
      if (xray.fingerprint) params.set('fp', xray.fingerprint);
      if (xray.network) params.set('type', xray.network);
      if (xray.host) params.set('host', xray.host);
      if (xray.path) params.set('path', xray.path);
      if (xray.serviceName) params.set('serviceName', xray.serviceName);
      return `trojan://${encodeURIComponent(xray.password ?? '')}@${node.host}:${node.port}?${params.toString()}${hash}`;
    }
    case 'shadowsocks': {
      const userInfo = Buffer.from(`${xray.method ?? ''}:${xray.password ?? ''}`, 'utf8').toString('base64').replace(/=+$/, '');
      return `ss://${userInfo}@${node.host}:${node.port}${hash}`;
    }
    case 'vmess': {
      const payload = {
        v: '2',
        ps: node.name,
        add: node.host,
        port: String(node.port),
        id: xray.uuid ?? '',
        aid: String(xray.alterId ?? 0),
        scy: 'auto',
        net: xray.network || 'tcp',
        type: 'none',
        host: xray.host || '',
        path: xray.path || '',
        tls: xray.security === 'tls' ? 'tls' : '',
        sni: xray.sni || '',
      };
      return `vmess://${encodeBase64Json(payload)}${hash}`;
    }
    default:
      return null;
  }
}

export function isXrayProtocol(value: string): value is XrayProtocol {
  return XRAY_PROTOCOLS.includes(value as XrayProtocol);
}

export function isProxyScheme(value: string): value is ProxyScheme {
  return PROXY_SCHEMES.includes(value as ProxyScheme);
}
