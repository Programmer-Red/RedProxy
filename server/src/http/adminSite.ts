import cookieParser from 'cookie-parser';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { buildXrayConfig } from '../xray';
import { createNodeSchema, importPayloadSchema } from '../nodes';
import type { AppServices } from '../services';
import type { NodeRecord, XraySettings } from '../types';
import { asyncHandler, clientIp, cookieOptions, errorHandler, HttpError, serveSiteAsset, throwValidation } from './common';

export const ADMIN_COOKIE_NAME = 'redproxy_admin';

export interface AdminSiteOptions {
  services: AppServices;
  publicDir: string;
  templateDir: string | null;
}

function parseImportText(text: string): { json: Array<Record<string, unknown>>; links: string[] } {
  const trimmed = text.trim();
  if (!trimmed) return { json: [], links: [] };

  const json: Array<Record<string, unknown>> = [];
  const links: string[] = [];

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

/**
 * The administrator portal. It is served on a separate port/host from the
 * end-user portal and uses its own cookie, so the two login sessions never mix.
 */
export function createAdminSite(options: AdminSiteOptions): express.Express {
  const { config, audit, nodes, sessions, auth, rateLimiter, settings } = options.services;
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

  const requireAdminAuth = (req: Request, res: Response, next: NextFunction): void => {
    const token = typeof req.cookies[ADMIN_COOKIE_NAME] === 'string' ? req.cookies[ADMIN_COOKIE_NAME] : undefined;
    const record = auth.validateToken(token, 'admin');
    if (!record || !token) {
      next(new HttpError(401, 'unauthorized', 'Administrator login required'));
      return;
    }
    res.locals.authToken = token;
    next();
  };

  app.get('/healthz', (_req, res) => {
    res.json({
      status: 'ok',
      site: 'admin',
      uptimeSeconds: Math.floor(process.uptime()),
      timestamp: new Date(options.services.config.nodeEnv === 'test' ? Date.now() : Date.now()).toISOString(),
    });
  });

  app.get('/api/auth/mode', (_req, res) => {
    const mode = settings.get().adminAuthMode;
    res.json({
      authMode: mode,
      passwordRequired: mode === 'password' || mode === 'totp_password',
      totpRequired: mode === 'totp' || mode === 'totp_password',
    });
  });

  app.post(
    '/api/auth/totp',
    asyncHandler(async (req, res) => {
      const parsed = z
        .object({
          token: z.string().regex(/^\d{6}$/, 'token must be exactly 6 digits').optional(),
          password: z.string().max(512).optional(),
          username: z.string().max(128).optional(),
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

      const mode = settings.get().adminAuthMode;
      const result = settings.verifyLogin(mode, parsed.data);
      if (!result.ok) {
        const after = rateLimiter.recordFailure(ip);
        audit.record('admin_login_failed', { ip, meta: { mode, reason: result.reason, banned: after.banned } });
        throw new HttpError(401, 'invalid_credentials', 'Invalid credentials', {
          attemptsRemaining: after.attemptsRemaining,
          banned: after.banned,
          retryAfterSeconds: after.retryAfterSeconds,
        });
      }

      rateLimiter.clear(ip);
      const created = auth.createSession('admin');
      res.cookie(ADMIN_COOKIE_NAME, created.token, cookieOptions(config));
      audit.record('admin_login', { ip, meta: { expiresAt: created.record.expiresAt, mode } });
      res.json({ authenticated: true, expiresAt: created.record.expiresAt, mustChangePassword: settings.get().mustChangePassword });
    }),
  );

  app.post(
    '/api/auth/logout',
    asyncHandler(async (req, res) => {
      const token = typeof req.cookies[ADMIN_COOKIE_NAME] === 'string' ? req.cookies[ADMIN_COOKIE_NAME] : undefined;
      auth.revokeToken(token, 'admin');
      res.clearCookie(ADMIN_COOKIE_NAME, { path: '/' });
      res.json({ authenticated: false });
    }),
  );

  app.get('/api/me', (req, res, next) => {
    const token = typeof req.cookies[ADMIN_COOKIE_NAME] === 'string' ? req.cookies[ADMIN_COOKIE_NAME] : undefined;
    const record = auth.validateToken(token, 'admin');
    if (!record) {
      next(new HttpError(401, 'unauthorized', 'Administrator login required'));
      return;
    }
    res.json({
      authenticated: true,
      expiresAt: record.expiresAt,
      authMode: settings.get().adminAuthMode,
      mustChangePassword: settings.get().mustChangePassword,
    });
  });

  // ---------------------------------------------------------------- settings
  app.get(
    '/api/settings',
    requireAdminAuth,
    asyncHandler(async (_req, res) => {
      res.json(await settings.toPublic());
    }),
  );

  app.patch(
    '/api/settings',
    requireAdminAuth,
    asyncHandler(async (req, res) => {
      const parsed = z
        .object({
          adminAuthMode: z.enum(['password', 'totp', 'totp_password']).optional(),
          userAuthMode: z.enum(['password', 'totp', 'totp_password']).optional(),
          username: z.string().trim().min(1).max(64).optional(),
        })
        .safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      try {
        if (parsed.data.adminAuthMode) settings.setAdminAuthMode(parsed.data.adminAuthMode);
        if (parsed.data.userAuthMode) settings.setUserAuthMode(parsed.data.userAuthMode);
        if (parsed.data.username) settings.setUsername(parsed.data.username);
      } catch (error) {
        if (error instanceof Error && error.message === 'password_required') {
          throw new HttpError(409, 'password_required', 'Set a password before enabling password authentication');
        }
        if (error instanceof Error && error.message === 'totp_required') {
          throw new HttpError(409, 'totp_required', 'Generate a TOTP secret before enabling TOTP authentication');
        }
        throw error;
      }
      audit.record('settings_changed', {
        meta: {
          adminAuthMode: parsed.data.adminAuthMode,
          userAuthMode: parsed.data.userAuthMode,
          username: parsed.data.username,
        },
      });
      res.json(await settings.toPublic());
    }),
  );

  app.post(
    '/api/settings/password',
    requireAdminAuth,
    asyncHandler(async (req, res) => {
      const parsed = z.object({ password: z.string().min(8).max(512) }).safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      settings.setPassword(parsed.data.password);
      audit.record('admin_password_changed');
      res.json(await settings.toPublic());
    }),
  );

  app.delete(
    '/api/settings/password',
    requireAdminAuth,
    asyncHandler(async (_req, res) => {
      settings.clearPassword();
      audit.record('admin_password_cleared');
      res.json(await settings.toPublic());
    }),
  );

  app.post(
    '/api/settings/totp/regenerate',
    requireAdminAuth,
    asyncHandler(async (req, res) => {
      const parsed = z.object({ currentTotp: z.string().regex(/^\d{6}$/) }).safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      if (!settings.verifyTotp(parsed.data.currentTotp)) {
        throw new HttpError(401, 'invalid_totp', 'Current TOTP code is invalid');
      }
      settings.regenerateTotpSecret();
      audit.record('totp_secret_regenerated');
      res.json(await settings.toPublic());
    }),
  );

  app.get(
    '/api/login-bans',
    requireAdminAuth,
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
    '/api/login-bans/:ip',
    requireAdminAuth,
    asyncHandler(async (req, res) => {
      const ip = req.params.ip;
      if (!ip) throw new HttpError(400, 'invalid_ip', 'IP is required');
      const removed = rateLimiter.unban(ip);
      if (!removed) throw new HttpError(404, 'not_banned', 'That IP is not currently banned');
      audit.record('ip_unbanned', { ip });
      res.json({ unbaned: true, ip });
    }),
  );

  // ---------------------------------------------------------------- nodes
  app.get(
    '/api/nodes',
    requireAdminAuth,
    asyncHandler(async (_req, res) => {
      res.json({ nodes: nodes.listPublic() });
    }),
  );

  app.post(
    '/api/nodes',
    requireAdminAuth,
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
    '/api/nodes/:id',
    requireAdminAuth,
    asyncHandler(async (req, res) => {
      const id = req.params.id;
      if (!id) throw new HttpError(400, 'invalid_node_id', 'Node id is required');
      const parsed = z
        .object({ enabled: z.boolean().optional(), name: z.string().trim().min(1).max(64).optional() })
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
    '/api/nodes/:id',
    requireAdminAuth,
    asyncHandler(async (req, res) => {
      const id = req.params.id;
      if (!id) throw new HttpError(400, 'invalid_node_id', 'Node id is required');
      if (!nodes.delete(id)) throw new HttpError(404, 'node_not_found', 'Node not found');
      audit.record('node_deleted', { nodeId: id });
      res.status(204).end();
    }),
  );

  app.post(
    '/api/nodes/import',
    requireAdminAuth,
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
    '/api/nodes/export',
    requireAdminAuth,
    asyncHandler(async (req, res) => {
      const includeSecrets = req.query.secrets !== 'false';
      res.setHeader('Content-Disposition', 'attachment; filename="redproxy-nodes.json"');
      res.json({
        version: 1,
        exportedAt: new Date().toISOString(),
        includeSecrets,
        nodes: nodes.exportJson(includeSecrets),
      });
    }),
  );

  app.get(
    '/api/nodes/export/links',
    requireAdminAuth,
    asyncHandler(async (_req, res) => {
      res.json({ links: nodes.exportShareLinks() });
    }),
  );

  // ---------------------------------------------------------------- xray
  app.get(
    '/api/xray/config/:id',
    requireAdminAuth,
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
        res.setHeader('Content-Disposition', `attachment; filename="${node.id}-xray.json"`);
      }
      res.json(xrayConfig);
    }),
  );

  app.post(
    '/api/xray/preview',
    requireAdminAuth,
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
        createdAt: Date.now(),
        xray: parsed.data.xray as XraySettings,
        localScheme: parsed.data.localScheme ?? 'socks5',
        localHost: parsed.data.localHost ?? '127.0.0.1',
        localPort: parsed.data.localPort ?? 10808,
      };
      res.json({ config: buildXrayConfig(record) });
    }),
  );

  // ---------------------------------------------------------------- sessions / audit
  app.get(
    '/api/sessions',
    requireAdminAuth,
    asyncHandler(async (_req, res) => {
      sessions.sweep();
      res.json({ sessions: sessions.listPublic(), maxConcurrentDevices: config.maxConcurrentDevices });
    }),
  );

  app.delete(
    '/api/sessions/:id',
    requireAdminAuth,
    asyncHandler(async (req, res) => {
      const id = req.params.id;
      if (!id) throw new HttpError(400, 'invalid_session_id', 'Session id is required');
      const session = sessions.revoke(id, 'admin_revoked', clientIp(req));
      if (!session) throw new HttpError(404, 'session_not_found', 'Session not found');
      res.json({ revoked: true, session: sessions.toPublic(session) });
    }),
  );

  app.get(
    '/api/events',
    requireAdminAuth,
    asyncHandler(async (_req, res) => {
      res.json({ events: audit.list() });
    }),
  );

  app.use('/api', (_req, _res, next) => {
    next(new HttpError(404, 'api_not_found', 'API route not found'));
  });

  app.get('*', (req, res, next) => {
    serveSiteAsset(req, res, next, { site: 'admin', publicDir: options.publicDir });
  });

  app.use(errorHandler());

  return app;
}
