import crypto from 'node:crypto';
import net from 'node:net';
import { z } from 'zod';
import { buildShareLink, isProxyScheme, parseShareLink } from './xray';
import type { ExtensionNodeConfig, NodeRecord, ProxyScheme, PublicNode, XraySettings } from './types';

const hostRefinement = z.string().trim().min(1).max(253).refine(value => {
  if (value === 'localhost') return true;
  if (net.isIP(value) !== 0) return true;
  if (value.startsWith('[') && value.endsWith(']') && net.isIP(value.slice(1, -1)) !== 0) return true;
  if (value.length > 253) return false;
  return /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(value);
}, 'host must be a valid hostname, IPv4 address, or bracketed IPv6 address');

export const nodeIdSchema = z.string().trim().min(1).max(64).regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/);
export const proxySchemeSchema = z.enum(['http', 'https', 'socks4', 'socks5']);
export const xrayProtocolSchema = z.enum(['vless', 'vmess', 'trojan', 'shadowsocks']);

export const xraySettingsSchema = z.object({
  protocol: xrayProtocolSchema,
  uuid: z.string().trim().max(128).nullable().optional(),
  alterId: z.coerce.number().int().min(0).max(65535).nullable().optional(),
  password: z.string().max(512).nullable().optional(),
  method: z.string().trim().max(128).nullable().optional(),
  flow: z.string().trim().max(128).nullable().optional(),
  network: z.enum(['tcp', 'ws', 'grpc', 'http', 'kcp', 'quic', 'xhttp']).nullable().optional(),
  security: z.enum(['none', 'tls', 'reality']).nullable().optional(),
  sni: z.string().trim().max(253).nullable().optional(),
  fingerprint: z.string().trim().max(64).nullable().optional(),
  publicKey: z.string().trim().max(256).nullable().optional(),
  shortId: z.string().trim().max(64).nullable().optional(),
  spiderX: z.string().trim().max(256).nullable().optional(),
  host: z.string().trim().max(253).nullable().optional(),
  path: z.string().trim().max(1024).nullable().optional(),
  serviceName: z.string().trim().max(256).nullable().optional(),
  allowInsecure: z.boolean().nullable().optional(),
});

export const createNodeSchema = z
  .object({
    id: nodeIdSchema.optional(),
    name: z.string().trim().min(1).max(64),
    kind: z.enum(['proxy', 'xray']).default('proxy'),
    scheme: proxySchemeSchema.default('http'),
    host: hostRefinement,
    port: z.coerce.number().int().min(1).max(65535),
    username: z.string().max(256).nullable().optional(),
    password: z.string().max(512).nullable().optional(),
    enabled: z.boolean().optional(),
    xray: xraySettingsSchema.optional(),
    localScheme: proxySchemeSchema.optional(),
    localHost: hostRefinement.optional(),
    localPort: z.coerce.number().int().min(1).max(65535).optional(),
    source: z.string().max(4096).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.kind === 'xray') {
      if (!value.xray) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'xray settings are required when kind=xray', path: ['xray'] });
      }
      if (value.xray?.protocol === 'vless' && !value.xray.uuid) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'vless requires uuid', path: ['xray', 'uuid'] });
      }
      if (value.xray?.protocol === 'vmess' && !value.xray.uuid) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'vmess requires uuid', path: ['xray', 'uuid'] });
      }
      if (value.xray?.protocol === 'trojan' && !value.xray.password) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'trojan requires password', path: ['xray', 'password'] });
      }
      if (value.xray?.protocol === 'shadowsocks' && (!value.xray.method || !value.xray.password)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'shadowsocks requires method and password', path: ['xray'] });
      }
    }
  });

export type CreateNodeInput = z.infer<typeof createNodeSchema>;

export const importPayloadSchema = z.object({
  nodes: z.array(z.record(z.unknown())).max(500).optional(),
  links: z.array(z.string().max(8192)).max(500).optional(),
  text: z.string().max(2_000_000).optional(),
  replace: z.boolean().optional(),
});

function slugify(value: string): string {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  return slug || 'node';
}

function redactXray(xray: XraySettings): Omit<XraySettings, 'password'> {
  const { password: _password, ...rest } = xray;
  return rest;
}

export class NodeService {
  private nodes = new Map<string, NodeRecord>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  listAll(): NodeRecord[] {
    return [...this.nodes.values()].sort((a, b) => a.createdAt - b.createdAt || a.id.localeCompare(b.id));
  }

  listPublic(): PublicNode[] {
    return this.listAll().map(node => this.toPublic(node));
  }

  get(id: string): NodeRecord | undefined {
    return this.nodes.get(id);
  }

  requireEnabled(id: string): NodeRecord {
    const node = this.nodes.get(id);
    if (!node) throw new Error(`node_not_found:${id}`);
    if (!node.enabled) throw new Error(`node_disabled:${id}`);
    return node;
  }

  create(input: CreateNodeInput): NodeRecord {
    const id = input.id ?? this.uniqueId(slugify(input.name));
    if (this.nodes.has(id)) throw new Error(`node_exists:${id}`);
    const kind = input.kind ?? 'proxy';
    const record: NodeRecord = {
      id,
      name: input.name.trim(),
      kind,
      scheme: input.scheme as ProxyScheme,
      host: input.host.trim(),
      port: input.port,
      username: input.username?.trim() || null,
      password: input.password || null,
      enabled: input.enabled ?? true,
      createdAt: this.now(),
      xray: input.xray as XraySettings | undefined,
      localScheme: input.localScheme ?? (kind === 'xray' ? 'socks5' : undefined),
      localHost: input.localHost ?? (kind === 'xray' ? '127.0.0.1' : undefined),
      localPort: input.localPort ?? (kind === 'xray' ? 10808 : undefined),
      source: input.source,
    };
    this.nodes.set(id, record);
    return record;
  }

  setEnabled(id: string, enabled: boolean): NodeRecord | null {
    const node = this.nodes.get(id);
    if (!node) return null;
    node.enabled = enabled;
    return node;
  }

  delete(id: string): boolean {
    return this.nodes.delete(id);
  }

  replaceAll(records: NodeRecord[]): void {
    this.nodes = new Map(records.map(record => [record.id, record]));
  }

  /** Ensure an id is unique inside this service without colliding with existing nodes. */
  ensureUniqueId(preferred: string): string {
    if (!this.nodes.has(preferred)) return preferred;
    return this.uniqueId(slugify(preferred));
  }

  toPublic(node: NodeRecord): PublicNode {
    return {
      id: node.id,
      name: node.name,
      kind: node.kind,
      scheme: node.scheme,
      host: node.host,
      port: node.port,
      enabled: node.enabled,
      hasAuth: Boolean(node.username || node.password || node.xray?.password),
      xray: node.xray ? redactXray(node.xray) : undefined,
      localScheme: node.localScheme,
      localHost: node.localHost,
      localPort: node.localPort,
      source: node.source,
    };
  }

  /** The browser extension can only speak http/https/socks4/socks5. */
  toExtensionConfig(node: NodeRecord): ExtensionNodeConfig {
    if (node.kind === 'xray') {
      const scheme = node.localScheme && isProxyScheme(node.localScheme) ? node.localScheme : 'socks5';
      return {
        id: node.id,
        name: node.name,
        scheme,
        host: node.localHost || '127.0.0.1',
        port: node.localPort || 10808,
        username: null,
        password: null,
      };
    }
    return {
      id: node.id,
      name: node.name,
      scheme: node.scheme,
      host: node.host,
      port: node.port,
      username: node.username,
      password: node.password,
    };
  }

  exportJson(includeSecrets = true): Array<Record<string, unknown>> {
    return this.listAll().map(node => {
      const base: Record<string, unknown> = {
        id: node.id,
        name: node.name,
        kind: node.kind,
        scheme: node.scheme,
        host: node.host,
        port: node.port,
        enabled: node.enabled,
      };
      if (node.kind === 'proxy') {
        base.username = node.username;
        base.password = includeSecrets ? node.password : node.password ? '***' : null;
      } else {
        base.xray = node.xray
          ? includeSecrets
            ? node.xray
            : redactXray(node.xray)
          : undefined;
        base.localScheme = node.localScheme;
        base.localHost = node.localHost;
        base.localPort = node.localPort;
      }
      if (includeSecrets && node.source) base.source = node.source;
      return base;
    });
  }

  exportShareLinks(): string[] {
    return this.listAll()
      .map(node => buildShareLink(node))
      .filter((link): link is string => Boolean(link));
  }

  importJsonRecords(records: Array<Record<string, unknown>>): { imported: NodeRecord[]; errors: Array<{ index: number; message: string }> } {
    const imported: NodeRecord[] = [];
    const errors: Array<{ index: number; message: string }> = [];
    records.forEach((raw, index) => {
      const parsed = createNodeSchema.safeParse(raw);
      if (!parsed.success) {
        errors.push({ index, message: parsed.error.issues.map(issue => `${issue.path.join('.')}: ${issue.message}`).join('; ') });
        return;
      }
      try {
        const payload = { ...parsed.data };
        if (payload.id) payload.id = this.ensureUniqueId(payload.id);
        imported.push(this.create(payload));
      } catch (error) {
        errors.push({ index, message: error instanceof Error ? error.message : 'unknown error' });
      }
    });
    return { imported, errors };
  }

  importShareLinks(links: string[]): { imported: NodeRecord[]; errors: Array<{ index: number; message: string }> } {
    const imported: NodeRecord[] = [];
    const errors: Array<{ index: number; message: string }> = [];
    links.forEach((link, index) => {
      const parsed = parseShareLink(link);
      if (!parsed) {
        errors.push({ index, message: 'unsupported or invalid share link' });
        return;
      }
      try {
        const candidate = createNodeSchema.parse(parsed);
        candidate.id = candidate.id ?? this.uniqueId(slugify(candidate.name));
        imported.push(this.create(candidate));
      } catch (error) {
        errors.push({ index, message: error instanceof Error ? error.message : 'invalid node' });
      }
    });
    return { imported, errors };
  }

  private uniqueId(base: string): string {
    let candidate = base;
    let index = 2;
    while (this.nodes.has(candidate)) {
      candidate = `${base}-${index}`;
      index += 1;
    }
    return candidate;
  }
}

export function randomNodeId(prefix = 'node'): string {
  return `${prefix}-${crypto.randomBytes(4).toString('hex')}`;
}
