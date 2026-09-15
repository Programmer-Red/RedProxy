import crypto from 'node:crypto';
import net from 'node:net';
import { z } from 'zod';
import type { ExtensionNodeConfig, NodeRecord, PublicNode, ProxyScheme } from './types';

const hostRefinement = z.string().trim().min(1).max(253).refine(value => {
  if (value === 'localhost') return true;
  if (net.isIP(value) !== 0) return true;
  // Bracketed IPv6 literal.
  if (value.startsWith('[') && value.endsWith(']') && net.isIP(value.slice(1, -1)) !== 0) return true;
  if (value.length > 253) return false;
  return /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(value);
}, 'host must be a valid hostname, IPv4 address, or bracketed IPv6 address');

export const nodeIdSchema = z.string().trim().min(1).max(64).regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/);
export const createNodeSchema = z.object({
  id: nodeIdSchema.optional(),
  name: z.string().trim().min(1).max(64),
  scheme: z.enum(['http', 'https', 'socks5']),
  host: hostRefinement,
  port: z.number().int().min(1).max(65535),
  username: z.string().max(256).nullable().optional(),
  password: z.string().max(256).nullable().optional(),
  enabled: z.boolean().optional(),
});

export type CreateNodeInput = z.infer<typeof createNodeSchema>;

function slugify(value: string): string {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  return slug || 'node';
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
    if (!node) {
      throw new Error(`node_not_found:${id}`);
    }
    if (!node.enabled) {
      throw new Error(`node_disabled:${id}`);
    }
    return node;
  }

  create(input: CreateNodeInput): NodeRecord {
    const id = input.id ?? this.uniqueId(slugify(input.name));
    if (this.nodes.has(id)) {
      throw new Error(`node_exists:${id}`);
    }
    const record: NodeRecord = {
      id,
      name: input.name.trim(),
      scheme: input.scheme as ProxyScheme,
      host: input.host.trim(),
      port: input.port,
      username: input.username?.trim() || null,
      password: input.password || null,
      enabled: input.enabled ?? true,
      createdAt: this.now(),
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

  toPublic(node: NodeRecord): PublicNode {
    return {
      id: node.id,
      name: node.name,
      scheme: node.scheme,
      host: node.host,
      port: node.port,
      enabled: node.enabled,
      hasAuth: Boolean(node.username || node.password),
    };
  }

  toExtensionConfig(node: NodeRecord): ExtensionNodeConfig {
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
