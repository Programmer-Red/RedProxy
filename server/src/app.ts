import path from 'node:path';
import cookieParser from 'cookie-parser';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { readAsset } from './assets';
import { AuditLog } from './audit';
import { AuthService, LoginRateLimiter, extractBearerToken } from './auth';
import { ensureDataDir, loadConfig } from './config';
import { buildExtensionArtifacts, buildRuntimeConfig, sanitizeFileToken } from './extension';
import { createNodeSchema, importPayloadSchema, NodeService } from './nodes';
import { ConcurrentDeviceLimitError, InvalidExtensionTokenError, SessionService } from './sessions';
import { SettingsService } from './settings';
import { buildXrayConfig } from './xray';
import type { AppConfig, NodeRecord, SessionRecord, XraySettings } from './types';

export const AUTH_COOKIE_NAME = 'redproxy_auth';

export interface CreateAppOptions {
  config?: AppConfig;
  now?: () => number;
  totpSecret?: string;
  publicDir?: string;
  templateDir?: string;
}

export interface AppServices {
  config: AppConfig;
  audit: AuditLog;
  nodes: NodeService;
  sessions: SessionService;
  auth: AuthService;
  rateLimiter: LoginRateLimiter;
  settings: SettingsService;
}

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

function asyncHandler(handler: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function clientIp(req: Request): string {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

function throwValidation(error: z.ZodError): never {
  throw new HttpError(400, 'invalid_request', 'Request validation failed', {
    issues: error.issues.map(issue => ({ path: issue.path.join('.'), message: issue.message })),
  });
}

function cookieOptions(config: AppConfig) {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: config.cookieSecure,
    maxAge: config.authSessionTtlSeconds * 1000,
    path: '/',
  };
}

function frontendContentType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.html':
      return 'text/html; charset=utf-8';
    case '.js':
      return 'text/javascript; charset=utf-8';
    case '.css':
      return 'text/css; charset=utf-8';
    case '.svg':
      return 'image/svg+xml';
    case '.png':
      return 'image/png';
    case '.ico':
      return 'image/x-icon';
    case '.json':
      return 'application/json; charset=utf-8';
    default:
      return 'application/octet-stream';
  }
}

function parseImportText(text: string): { json: Array<Record<string, unknown>>; links: string[] } {
  const trimmed = text.trim();
  if (!trimmed) return { json: [], links: [] };

  const json: Array<Record<string, unknown>> = [];
  const links: string[] = [];

  // The whole payload may be a JSON document (array or {nodes,links}).
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (Array.isArray(parsed)) {
      json.push(...(parsed as Array<Record<string, unknown>>));
      return { json, links };
    }
    if (parsed && typeof parsed === 'object' && Array.isArray((parsed as { nodes?: unknown }).nodes)) {
      json.push(...((parsed as { nodes: Array<Record<string, unknown>> }).nodes));
      if (Array.isArray((parsed as { links?: unknown }).links)) {
        links.push(...((parsed as { links: string[] }).links));
      }
      return { json, links };
    }
    if (parsed && typeof parsed === 'object') {
      json.push(parsed as Record<string, unknown>);
      return { json, links };
    }
  } catch {
    // Not a single JSON document; fall through to line-by-line parsing.
  }

  for (const rawLine of trimmed.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith('{') || line.startsWith('[')) {
      try {
        const parsed = JSON.parse(line) as unknown;
        if (Array.isArray(parsed)) json.push(...(parsed as Array<Record<string, unknown>>));
        else if (parsed && typeof parsed === 'object') json.push(parsed as Record<string, unknown>);
        else throw new Error('JSON line is not an object');
      } catch (error) {
        throw new HttpError(400, 'invalid_import', `Could not parse import line as JSON: ${String(error)}`);
      }
    } else {
      links.push(line);
    }
  }
  return { json, links };
}

export function createApp(options: CreateAppOptions = {}): { app: express.Express; services: AppServices } {
  const config = options.config ?? loadConfig();
  ensureDataDir(config);
  const now = options.now ?? (() => Date.now());
  const publicDir = options.publicDir ?? config.staticDir ?? path.resolve(process.cwd(), 'public');
  const templateDir = options.templateDir ?? config.templateDir ?? path.resolve(process.cwd(), 'extension-template');

  const settings = new SettingsService(config, now, options.totpSecret ?? null);

  const audit = new AuditLog();
  const nodes = new NodeService(now);
  const sessions = new SessionService(config, nodes, audit, now);
  const auth = new AuthService(config, now);
  const rateLimiter = new LoginRateLimiter(config.loginMaxAttempts, config.loginWindowSeconds, config.loginBanSeconds, now);

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: false, limit: '2mb' }));
  app.use(cookieParser());
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
    next();
  });

  const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
    const token = typeof req.cookies[AUTH_COOKIE_NAME] === 'string' ? req.cookies[AUTH_COOKIE_NAME] : undefined;
    const record = auth.validateToken(token);
    if (!record || !token) {
      next(new HttpError(401, 'unauthorized', 'Login required'));
      return;
    }
    res.locals.authToken = token;
    res.locals.ownerHash = auth.hashToken(token);
    next();
  };

  const requireExtensionAuth = (req: Request, res: Response, next: NextFunction): void => {
    const token = extractBearerToken(req.header('authorization'));
    if (!token) {
      next(new HttpError(401, 'missing_extension_token', 'Authorization: Bearer <extensionToken> is required'));
      return;
    }
    res.locals.extensionToken = token;
    next();
  };

  const requireSecureExtensionTransport = (): void => {
    if (config.nodeEnv === 'production' && !config.publicBaseUrl.startsWith('https://') && !config.allowInsecureHttp) {
      throw new HttpError(
        503,
        'https_required',
        'Refusing to distribute extension tokens over plain HTTP in production. Configure HTTPS or set ALLOW_INSECURE_HTTP=true for local-only testing.',
      );
    }
  };

  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', uptimeSeconds: Math.floor(process.uptime()), timestamp: new Date(now()).toISOString() });
  });

  app.get('/api/config', (_req, res) => {
    const ttlOptions = [300, 600, 900, 1800, 3600, 7200, 14400, 28800, 86400].filter(value => value <= config.sessionTtlSeconds);
    if (!ttlOptions.includes(config.sessionTtlSeconds)) ttlOptions.push(config.sessionTtlSeconds);
    ttlOptions.sort((a, b) => a - b);
    res.json({
      maxConcurrentDevices: config.maxConcurrentDevices,
      sessionTtlSeconds: config.sessionTtlSeconds,
      sessionIdleSeconds: config.sessionIdleSeconds,
      enrollmentTtlSeconds: config.enrollmentTtlSeconds,
      heartbeatIntervalSeconds: 15,
      loginMaxAttempts: config.loginMaxAttempts,
      loginWindowSeconds: config.loginWindowSeconds,
      loginBanSeconds: config.loginBanSeconds,
      authMode: settings.getAuthMode(),
      hasPassword: Boolean(settings.get().passwordHash),
      ttlOptions,
    });
  });

  app.get('/api/auth/mode', (_req, res) => {
    res.json({
      authMode: settings.getAuthMode(),
      hasPassword: Boolean(settings.get().passwordHash),
    });
  });

  app.post(
    '/api/auth/totp',
    asyncHandler(async (req, res) => {
      const parsed = z
        .object({
          token: z.string().regex(/^\d{6}$/, 'token must be exactly 6 digits'),
          password: z.string().max(512).optional(),
        })
        .safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);

      const ip = clientIp(req);
      const decision = rateLimiter.check(ip);
      if (!decision.allowed) {
        res.setHeader('Retry-After', String(decision.retryAfterSeconds));
        throw new HttpError(429, decision.banned ? 'ip_banned' : 'rate_limited', `Too many failed login attempts. Retry in ${decision.retryAfterSeconds}s.`, {
          banned: decision.banned,
          retryAfterSeconds: decision.retryAfterSeconds,
        });
      }

      const totpOk = settings.verifyUserTotp(parsed.data.token);
      const passwordRequired = settings.getAuthMode() === 'totp_password';
      const passwordOk = !passwordRequired || settings.verifyUserPassword(parsed.data.password ?? '');
      if (!totpOk || !passwordOk) {
        const after = rateLimiter.recordFailure(ip);
        audit.record('auth_login_failed', {
          ip,
          meta: { totpOk, passwordOk: passwordRequired ? passwordOk : null, banned: after.banned },
        });
        res.setHeader('Retry-After', String(after.banned ? after.retryAfterSeconds : 0));
        throw new HttpError(401, 'invalid_credentials', 'Invalid TOTP code or password', {
          attemptsRemaining: after.attemptsRemaining,
          banned: after.banned,
          retryAfterSeconds: after.retryAfterSeconds,
        });
      }

      rateLimiter.clear(ip);
      const created = auth.createSession();
      res.cookie(AUTH_COOKIE_NAME, created.token, cookieOptions(config));
      audit.record('auth_login', { ip, meta: { expiresAt: created.record.expiresAt, authMode: settings.getAuthMode() } });
      res.json({ authenticated: true, expiresAt: created.record.expiresAt });
    }),
  );

  app.post(
    '/api/auth/logout',
    asyncHandler(async (req, res) => {
      const token = typeof req.cookies[AUTH_COOKIE_NAME] === 'string' ? req.cookies[AUTH_COOKIE_NAME] : undefined;
      auth.revokeToken(token);
      res.clearCookie(AUTH_COOKIE_NAME, { path: '/' });
      res.json({ authenticated: false });
    }),
  );

  app.get('/api/me', (req, res, next) => {
    const token = typeof req.cookies[AUTH_COOKIE_NAME] === 'string' ? req.cookies[AUTH_COOKIE_NAME] : undefined;
    const record = auth.validateToken(token);
    if (!record) {
      next(new HttpError(401, 'unauthorized', 'Login required'));
      return;
    }
    res.json({ authenticated: true, expiresAt: record.expiresAt, authMode: settings.getAuthMode() });
  });

  // ---------------------------------------------------------------- admin: security
  app.get(
    '/api/admin/settings',
    requireAuth,
    asyncHandler(async (_req, res) => {
      res.json(await settings.toPublic());
    }),
  );

  app.get(
    '/api/admin/settings/totp',
    requireAuth,
    asyncHandler(async (_req, res) => {
      res.json(await settings.toPublic());
    }),
  );

  app.patch(
    '/api/admin/settings',
    requireAuth,
    asyncHandler(async (req, res) => {
      const parsed = z.object({ authMode: z.enum(['totp', 'totp_password']) }).safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      try {
        settings.setAuthMode(parsed.data.authMode);
      } catch (error) {
        if (error instanceof Error && error.message === 'password_required') {
          throw new HttpError(409, 'password_required', 'Set an admin password before switching to TOTP + password');
        }
        throw error;
      }
      audit.record('auth_mode_changed', { meta: { authMode: parsed.data.authMode } });
      res.json(await settings.toPublic());
    }),
  );

  app.post(
    '/api/admin/settings/password',
    requireAuth,
    asyncHandler(async (req, res) => {
      const parsed = z.object({ password: z.string().min(12).max(512) }).safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      settings.setPassword(parsed.data.password);
      audit.record('admin_password_changed');
      res.json(await settings.toPublic());
    }),
  );

  app.delete(
    '/api/admin/settings/password',
    requireAuth,
    asyncHandler(async (_req, res) => {
      settings.clearPassword();
      audit.record('admin_password_cleared');
      res.json(await settings.toPublic());
    }),
  );

  app.post(
    '/api/admin/settings/totp/regenerate',
    requireAuth,
    asyncHandler(async (req, res) => {
      const parsed = z.object({ currentTotp: z.string().regex(/^\d{6}$/) }).safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      if (!settings.verifyUserTotp(parsed.data.currentTotp)) {
        throw new HttpError(401, 'invalid_totp', 'Current TOTP code is invalid');
      }
      settings.regenerateTotpSecret();
      audit.record('totp_secret_regenerated');
      res.json(await settings.toPublic());
    }),
  );

  app.get(
    '/api/admin/login-bans',
    requireAuth,
    asyncHandler(async (_req, res) => {
      res.json({
        bans: rateLimiter.listBans(),
        config: {
          maxAttempts: config.loginMaxAttempts,
          windowSeconds: config.loginWindowSeconds,
          banSeconds: config.loginBanSeconds,
          key: config.trustProxy ? 'X-Forwarded-For/socket IP' : 'socket IP',
        },
      });
    }),
  );

  app.delete(
    '/api/admin/login-bans/:ip',
    requireAuth,
    asyncHandler(async (req, res) => {
      const ip = req.params.ip;
      if (!ip) throw new HttpError(400, 'invalid_ip', 'IP is required');
      const removed = rateLimiter.unban(ip);
      if (!removed) throw new HttpError(404, 'not_banned', 'That IP is not currently banned');
      audit.record('ip_unbanned', { ip });
      res.json({ unbaned: true, ip });
    }),
  );

  // ---------------------------------------------------------------- admin: nodes
  app.get(
    '/api/admin/nodes',
    requireAuth,
    asyncHandler(async (_req, res) => {
      res.json({ nodes: nodes.listPublic() });
    }),
  );

  app.post(
    '/api/admin/nodes',
    requireAuth,
    asyncHandler(async (req, res) => {
      const parsed = createNodeSchema.safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      try {
        const node = nodes.create(parsed.data);
        audit.record('node_created', {
          nodeId: node.id,
          meta: { kind: node.kind, scheme: node.scheme, host: node.host, port: node.port },
        });
        res.status(201).json({ node: nodes.toPublic(node) });
      } catch (error) {
        if (error instanceof Error && error.message.startsWith('node_exists:')) {
          throw new HttpError(409, 'node_exists', 'A node with this id already exists');
        }
        throw error;
      }
    }),
  );

  app.patch(
    '/api/admin/nodes/:id',
    requireAuth,
    asyncHandler(async (req, res) => {
      const id = req.params.id;
      if (!id) throw new HttpError(400, 'invalid_node_id', 'Node id is required');
      const parsed = z
        .object({
          enabled: z.boolean().optional(),
          name: z.string().trim().min(1).max(64).optional(),
        })
        .safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      const node = nodes.get(id);
      if (!node) throw new HttpError(404, 'node_not_found', 'Node not found');
      if (parsed.data.enabled !== undefined) nodes.setEnabled(id, parsed.data.enabled);
      if (parsed.data.name !== undefined) node.name = parsed.data.name;
      audit.record('node_updated', { nodeId: node.id, meta: { enabled: node.enabled, name: node.name } });
      res.json({ node: nodes.toPublic(node) });
    }),
  );

  app.delete(
    '/api/admin/nodes/:id',
    requireAuth,
    asyncHandler(async (req, res) => {
      const id = req.params.id;
      if (!id) throw new HttpError(400, 'invalid_node_id', 'Node id is required');
      if (!nodes.delete(id)) throw new HttpError(404, 'node_not_found', 'Node not found');
      audit.record('node_deleted', { nodeId: id });
      res.status(204).end();
    }),
  );

  app.post(
    '/api/admin/nodes/import',
    requireAuth,
    asyncHandler(async (req, res) => {
      const parsed = importPayloadSchema.safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      let jsonRecords = parsed.data.nodes ?? [];
      let links = parsed.data.links ?? [];
      if (parsed.data.text) {
        const fromText = parseImportText(parsed.data.text);
        jsonRecords = jsonRecords.concat(fromText.json);
        links = links.concat(fromText.links);
      }
      const jsonResult = jsonRecords.length > 0 ? nodes.importJsonRecords(jsonRecords) : { imported: [], errors: [] };
      const linkResult = links.length > 0 ? nodes.importShareLinks(links) : { imported: [], errors: [] };
      const imported = [...jsonResult.imported, ...linkResult.imported];
      const errors = [...jsonResult.errors, ...linkResult.errors];
      audit.record('nodes_imported', { meta: { imported: imported.length, errors: errors.length } });
      res.json({
        imported: imported.map(node => nodes.toPublic(node)),
        errors,
        importedCount: imported.length,
        errorCount: errors.length,
      });
    }),
  );

  app.get(
    '/api/admin/nodes/export',
    requireAuth,
    asyncHandler(async (req, res) => {
      const includeSecrets = req.query.secrets !== 'false';
      res.setHeader('Content-Disposition', 'attachment; filename="redproxy-nodes.json"');
      res.json({
        version: 1,
        exportedAt: new Date(now()).toISOString(),
        includeSecrets,
        nodes: nodes.exportJson(includeSecrets),
      });
    }),
  );

  app.get(
    '/api/admin/nodes/export/links',
    requireAuth,
    asyncHandler(async (_req, res) => {
      res.json({ links: nodes.exportShareLinks() });
    }),
  );

  // ---------------------------------------------------------------- admin: xray
  app.get(
    '/api/admin/xray/config/:id',
    requireAuth,
    asyncHandler(async (req, res) => {
      const id = req.params.id;
      if (!id) throw new HttpError(400, 'invalid_node_id', 'Node id is required');
      const node = nodes.get(id);
      if (!node) throw new HttpError(404, 'node_not_found', 'Node not found');
      if (node.kind !== 'xray' || !node.xray) throw new HttpError(400, 'not_xray_node', 'This node is not an Xray node');
      const parsed = z
        .object({
          inboundPort: z.coerce.number().int().min(1).max(65535).optional(),
          inboundProtocol: z.enum(['socks', 'http']).optional(),
        })
        .safeParse(req.query);
      if (!parsed.success) throwValidation(parsed.error);
      const xrayConfig = buildXrayConfig(node, {
        inboundPort: parsed.data.inboundPort ?? node.localPort ?? 10808,
        inboundProtocol: parsed.data.inboundProtocol,
      });
      if (req.query.download === 'true') {
        res.setHeader('Content-Disposition', `attachment; filename="${sanitizeFileToken(node.id)}-xray.json"`);
      }
      res.json(xrayConfig);
    }),
  );

  app.post(
    '/api/admin/xray/preview',
    requireAuth,
    asyncHandler(async (req, res) => {
      const parsed = createNodeSchema.safeParse({ ...req.body, kind: 'xray', enabled: true });
      if (!parsed.success) throwValidation(parsed.error);
      const record: NodeRecord = {
        id: parsed.data.id ?? 'preview',
        name: parsed.data.name,
        kind: 'xray',
        scheme: parsed.data.scheme,
        host: parsed.data.host,
        port: parsed.data.port,
        username: parsed.data.username ?? null,
        password: parsed.data.password ?? null,
        enabled: true,
        createdAt: now(),
        xray: parsed.data.xray as XraySettings,
        localScheme: parsed.data.localScheme ?? 'socks5',
        localHost: parsed.data.localHost ?? '127.0.0.1',
        localPort: parsed.data.localPort ?? 10808,
      };
      res.json({ config: buildXrayConfig(record) });
    }),
  );

  // ---------------------------------------------------------------- admin: sessions / audit
  app.get(
    '/api/admin/sessions',
    requireAuth,
    asyncHandler(async (_req, res) => {
      sessions.sweep();
      res.json({ sessions: sessions.listPublic(), maxConcurrentDevices: config.maxConcurrentDevices });
    }),
  );

  app.delete(
    '/api/admin/sessions/:id',
    requireAuth,
    asyncHandler(async (req, res) => {
      const id = req.params.id;
      if (!id) throw new HttpError(400, 'invalid_session_id', 'Session id is required');
      const session = sessions.revoke(id, 'admin_revoked', clientIp(req));
      if (!session) throw new HttpError(404, 'session_not_found', 'Session not found');
      res.json({ revoked: true, session: sessions.toPublic(session) });
    }),
  );

  app.get(
    '/api/admin/events',
    requireAuth,
    asyncHandler(async (_req, res) => {
      res.json({ events: audit.list() });
    }),
  );

  // ---------------------------------------------------------------- user session
  app.get(
    '/api/session',
    requireAuth,
    asyncHandler(async (_req, res) => {
      const ownerHash = String(res.locals.ownerHash);
      sessions.sweep();
      const session = sessions.getActiveCurrentForOwner(ownerHash) ?? sessions.getCurrentForOwner(ownerHash);
      res.json({ session: session ? sessions.toPublic(session) : null });
    }),
  );

  app.post(
    '/api/session',
    requireAuth,
    asyncHandler(async (req, res) => {
      const parsed = z
        .object({
          deviceId: z.string().trim().min(8).max(128).regex(/^[A-Za-z0-9_.:-]+$/, 'deviceId contains invalid characters'),
          nodeId: z.string().trim().min(1).max(64),
          ttlSeconds: z.coerce.number().int().min(60).max(config.sessionTtlSeconds).default(config.sessionTtlSeconds),
        })
        .safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      try {
        const session = sessions.create({
          ownerHash: String(res.locals.ownerHash),
          deviceId: parsed.data.deviceId,
          nodeId: parsed.data.nodeId,
          ttlSeconds: parsed.data.ttlSeconds,
          ip: clientIp(req),
          userAgent: req.header('user-agent') || 'unknown',
        });
        res.status(201).json({ session: sessions.toPublic(session) });
      } catch (error) {
        if (error instanceof ConcurrentDeviceLimitError) {
          throw new HttpError(429, 'concurrent_device_limit', `Maximum concurrent devices reached (${error.maxDevices})`);
        }
        if (error instanceof Error && error.message.startsWith('node_not_found:')) {
          throw new HttpError(404, 'node_not_found', 'Selected node no longer exists');
        }
        if (error instanceof Error && error.message.startsWith('node_disabled:')) {
          throw new HttpError(409, 'node_disabled', 'Selected node is disabled');
        }
        throw error;
      }
    }),
  );

  app.post(
    '/api/session/heartbeat',
    requireAuth,
    asyncHandler(async (req, res) => {
      const session = sessions.touchCurrentForOwner(String(res.locals.ownerHash), clientIp(req));
      if (!session) throw new HttpError(404, 'session_not_found', 'No active session');
      res.json({ session: sessions.toPublic(session) });
    }),
  );

  app.post(
    '/api/session/revoke',
    requireAuth,
    asyncHandler(async (req, res) => {
      const session = sessions.revokeCurrentForOwner(String(res.locals.ownerHash), 'page_revoke', clientIp(req));
      res.json({ revoked: Boolean(session), session: session ? sessions.toPublic(session) : null });
    }),
  );

  async function buildArtifactsForCurrentSession(res: Response, kind: 'crx' | 'zip'): Promise<{ body: Buffer; session: SessionRecord }> {
    requireSecureExtensionTransport();
    const ownerHash = String(res.locals.ownerHash);
    sessions.sweep();
    const session = sessions.getActiveCurrentForOwner(ownerHash);
    if (!session) throw new HttpError(404, 'session_not_found', 'No active temporary session');
    const node = nodes.get(session.nodeId);
    if (!node || !node.enabled) throw new HttpError(409, 'node_unavailable', 'The session node is missing or disabled');
    const extensionToken = sessions.issueExtensionToken(session.id);
    const runtimeConfig = buildRuntimeConfig(config, session, node, extensionToken, now());
    const artifacts = await buildExtensionArtifacts({
      runtimeConfig,
      keyPath: config.crxPrivateKeyPath,
      crxKeyBits: config.crxKeyBits,
      templateDir,
    });
    return { body: kind === 'crx' ? artifacts.crx : artifacts.zip, session };
  }

  app.get(
    '/api/session/extension.crx',
    requireAuth,
    asyncHandler(async (_req, res) => {
      const { body, session } = await buildArtifactsForCurrentSession(res, 'crx');
      res.setHeader('Content-Type', 'application/x-chrome-extension');
      res.setHeader('Content-Disposition', `attachment; filename="redproxy-${sanitizeFileToken(session.id)}.crx"`);
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.setHeader('Content-Length', String(body.length));
      res.end(body);
    }),
  );

  app.get(
    '/api/session/extension.zip',
    requireAuth,
    asyncHandler(async (_req, res) => {
      const { body, session } = await buildArtifactsForCurrentSession(res, 'zip');
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="redproxy-${sanitizeFileToken(session.id)}.zip"`);
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.setHeader('Content-Length', String(body.length));
      res.end(body);
    }),
  );

  app.post(
    '/api/extension/heartbeat',
    requireExtensionAuth,
    asyncHandler(async (req, res) => {
      try {
        const result = sessions.heartbeatByExtensionToken(String(res.locals.extensionToken), clientIp(req));
        res.json({
          ok: true,
          revoked: false,
          expiresAt: result.expiresAt,
          token: result.rotatedToken ?? undefined,
          rotated: Boolean(result.rotatedToken),
          session: sessions.toPublic(result.session),
        });
      } catch (error) {
        if (error instanceof InvalidExtensionTokenError) {
          throw new HttpError(401, 'invalid_extension_token', 'Extension token is invalid, expired, replayed, or revoked', {
            reason: error.reason,
          });
        }
        throw error;
      }
    }),
  );

  app.post(
    '/api/extension/revoke',
    requireExtensionAuth,
    asyncHandler(async (req, res) => {
      try {
        const session = sessions.revokeByExtensionToken(String(res.locals.extensionToken), 'extension_revoke', clientIp(req));
        res.json({ revoked: true, sessionId: session.id });
      } catch (error) {
        if (error instanceof InvalidExtensionTokenError) {
          throw new HttpError(401, 'invalid_extension_token', 'Extension token is invalid, expired, or revoked');
        }
        throw error;
      }
    }),
  );

  app.use('/api', (_req, _res, next) => {
    next(new HttpError(404, 'api_not_found', 'API route not found'));
  });

  // Serve the SPA from disk when present, otherwise from embedded assets so the
  // compiled single-file binary needs no sidecar directory.
  app.get('*', (req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      next();
      return;
    }
    let relative = req.path === '/' ? 'index.html' : req.path.replace(/^\//, '');
    if (!path.extname(relative)) relative = 'index.html';
    const key = `public/${relative}`;
    let content = readAsset(key, publicDir);
    let servedKey = relative;
    if (!content) {
      content = readAsset('public/index.html', publicDir);
      servedKey = 'index.html';
    }
    if (!content) {
      next();
      return;
    }
    res.setHeader('Content-Type', frontendContentType(servedKey));
    res.setHeader('Cache-Control', 'no-cache');
    res.send(content);
  });

  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof HttpError) {
      res.status(error.status).json({ error: error.code, message: error.message, details: error.details });
      return;
    }
    const message = error instanceof Error ? error.message : 'Unexpected server error';
    console.error('[RedProxy] unhandled error:', error);
    res.status(500).json({ error: 'internal_error', message });
  });

  setInterval(() => {
    try {
      sessions.sweep();
    } catch (error) {
      console.error('[RedProxy] session sweep failed:', error);
    }
  }, 10_000).unref();

  return { app, services: { config, audit, nodes, sessions, auth, rateLimiter, settings } };
}
