import cookieParser from 'cookie-parser';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { AuditLog } from './audit';
import {
  AuthService,
  LoginRateLimiter,
  buildOtpAuthUri,
  extractBearerToken,
  loadOrCreateTotpSecret,
  normalizeTotpSecret,
  verifyTotp,
} from './auth';
import { ensureDataDir, loadConfig } from './config';
import { buildExtensionArtifacts, buildRuntimeConfig, sanitizeFileToken } from './extension';
import { createNodeSchema, NodeService } from './nodes';
import { ConcurrentDeviceLimitError, InvalidExtensionTokenError, SessionNotFoundError, SessionService } from './sessions';
import type { AppConfig, SessionRecord } from './types';

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
  totp: { secretBase32: string; otpauthUri: string };
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

function extensionDownloadContentType(kind: 'crx' | 'zip'): string {
  return kind === 'crx' ? 'application/x-chrome-extension' : 'application/zip';
}

function setNoStore(res: Response, fileName: string): void {
  res.setHeader('Content-Type', extensionDownloadContentType(fileName.endsWith('.crx') ? 'crx' : 'zip'));
  res.setHeader('Content-Disposition', `attachment; filename="${sanitizeFileToken(fileName)}"`);
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
}

export function createApp(options: CreateAppOptions = {}): { app: express.Express; services: AppServices } {
  const config = options.config ?? loadConfig();
  ensureDataDir(config);
  const now = options.now ?? (() => Date.now());
  const publicDir = options.publicDir ?? `${process.cwd()}/public`;
  const templateDir = options.templateDir;

  const totp = options.totpSecret
    ? { secretBase32: normalizeTotpSecret(options.totpSecret), otpauthUri: buildOtpAuthUri(normalizeTotpSecret(options.totpSecret)) }
    : loadOrCreateTotpSecret(config);
  const audit = new AuditLog();
  const nodes = new NodeService(now);
  const sessions = new SessionService(config, nodes, audit, now);
  const auth = new AuthService(config, now);
  const rateLimiter = new LoginRateLimiter(config.loginMaxAttempts, config.loginWindowSeconds, now);

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: false, limit: '256kb' }));
  app.use(cookieParser());
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    if (req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
    }
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
    if (!ttlOptions.includes(config.sessionTtlSeconds)) {
      ttlOptions.push(config.sessionTtlSeconds);
    }
    ttlOptions.sort((a, b) => a - b);
    res.json({
      maxConcurrentDevices: config.maxConcurrentDevices,
      sessionTtlSeconds: config.sessionTtlSeconds,
      sessionIdleSeconds: config.sessionIdleSeconds,
      heartbeatIntervalSeconds: 15,
      ttlOptions,
    });
  });

  app.post(
    '/api/auth/totp',
    asyncHandler(async (req, res) => {
      const parsed = z.object({ token: z.string().regex(/^\d{6}$/, 'token must be exactly 6 digits') }).safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);

      const ip = clientIp(req);
      const limit = rateLimiter.check(ip);
      if (!limit.allowed) {
        res.setHeader('Retry-After', String(limit.retryAfterSeconds));
        throw new HttpError(429, 'rate_limited', `Too many failed login attempts. Retry in ${limit.retryAfterSeconds}s.`);
      }

      if (!verifyTotp(totp.secretBase32, parsed.data.token, now())) {
        rateLimiter.recordFailure(ip);
        const after = rateLimiter.check(ip);
        audit.record('auth_login_failed', { ip });
        throw new HttpError(401, 'invalid_totp', 'Invalid TOTP code', { attemptsRemaining: after.attemptsRemaining });
      }

      rateLimiter.clear(ip);
      const created = auth.createSession();
      res.cookie(AUTH_COOKIE_NAME, created.token, cookieOptions(config));
      audit.record('auth_login', { ip, meta: { expiresAt: created.record.expiresAt } });
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
    res.json({ authenticated: true, expiresAt: record.expiresAt });
  });

  app.get(
    '/api/admin/totp',
    requireAuth,
    asyncHandler(async (_req, res) => {
      res.json({ otpauthUri: buildOtpAuthUri(totp.secretBase32), issuer: 'RedProxy', label: 'admin' });
    }),
  );

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
        audit.record('node_created', { nodeId: node.id, meta: { scheme: node.scheme, host: node.host, port: node.port } });
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
      const parsed = z.object({ enabled: z.boolean() }).safeParse(req.body);
      if (!parsed.success) throwValidation(parsed.error);
      const node = nodes.setEnabled(id, parsed.data.enabled);
      if (!node) throw new HttpError(404, 'node_not_found', 'Node not found');
      audit.record('node_updated', { nodeId: node.id, meta: { enabled: node.enabled } });
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
      setNoStore(res, `redproxy-${sanitizeFileToken(session.id)}.crx`);
      res.setHeader('Content-Length', String(body.length));
      res.end(body);
    }),
  );

  app.get(
    '/api/session/extension.zip',
    requireAuth,
    asyncHandler(async (_req, res) => {
      const { body, session } = await buildArtifactsForCurrentSession(res, 'zip');
      setNoStore(res, `redproxy-${sanitizeFileToken(session.id)}.zip`);
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
        res.json({ ok: true, revoked: false, expiresAt: result.expiresAt, session: sessions.toPublic(result.session) });
      } catch (error) {
        if (error instanceof InvalidExtensionTokenError) {
          throw new HttpError(401, 'invalid_extension_token', 'Extension token is invalid, expired, or revoked');
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
        if (error instanceof InvalidExtensionTokenError || error instanceof SessionNotFoundError) {
          throw new HttpError(401, 'invalid_extension_token', 'Extension token is invalid, expired, or revoked');
        }
        throw error;
      }
    }),
  );

  app.use('/api', (_req, _res, next) => {
    next(new HttpError(404, 'api_not_found', 'API route not found'));
  });

  app.use(express.static(publicDir, { index: 'index.html', extensions: ['html'] }));
  app.get('*', (_req, res) => {
    res.sendFile(`${publicDir}/index.html`);
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

  return {
    app,
    services: { config, audit, nodes, sessions, auth, rateLimiter, totp },
  };
}
