import path from 'node:path';
import cookieParser from 'cookie-parser';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { AuditLog } from '../audit';
import { AuthService, LoginRateLimiter, extractBearerToken } from '../auth';
import { buildExtensionArtifacts, buildRuntimeConfig, sanitizeFileToken } from '../extension';
import { ProxyGateway } from '../proxy/gateway';
import { ConcurrentDeviceLimitError, InvalidExtensionTokenError, SessionService } from '../sessions';
import { SettingsService } from '../settings';
import type { AppConfig, SessionRecord } from '../types';
import { NodeService } from '../nodes';
import { asyncHandler, clientIp, cookieOptions, errorHandler, extensionCors, HttpError, serveSiteAsset, throwValidation } from './common';

export const USER_COOKIE_NAME = 'redproxy_user';

export interface UserSiteRuntime {
  app: express.Express;
  gateway: ProxyGateway;
  proxyRealm: string;
}

export interface UserSiteOptions {
  config: AppConfig;
  publicDir: string;
  templateDir: string | null;
  audit: AuditLog;
  nodes: NodeService;
  sessions: SessionService;
  auth: AuthService;
  rateLimiter: LoginRateLimiter;
  settings: SettingsService;
  now: () => number;
}

/**
 * The end-user portal. It only exposes node selection, session creation and
 * extension downloads - never node management or administrator settings.
 */
export function createUserSite(options: UserSiteOptions): UserSiteRuntime {
  const { config, audit, nodes, sessions, auth, rateLimiter, settings, now } = options;
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
    if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(extensionCors);

  const requireUserAuth = (req: Request, res: Response, next: NextFunction): void => {
    const token = typeof req.cookies[USER_COOKIE_NAME] === 'string' ? req.cookies[USER_COOKIE_NAME] : undefined;
    const record = auth.validateToken(token, 'user');
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
    res.json({
      status: 'ok',
      site: 'user',
      uptimeSeconds: Math.floor(process.uptime()),
      timestamp: new Date(now()).toISOString(),
    });
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
      ttlOptions,
      adminPortal: config.adminEnabled ? 'separate' : 'disabled',
    });
  });

  app.get('/api/auth/mode', (_req, res) => {
    const mode = settings.get().userAuthMode;
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

      const mode = settings.get().userAuthMode;
      const result = settings.verifyLogin(mode, parsed.data);
      if (!result.ok) {
        const after = rateLimiter.recordFailure(ip);
        audit.record('user_login_failed', { ip, meta: { mode, reason: result.reason, banned: after.banned } });
        throw new HttpError(401, 'invalid_credentials', 'Invalid credentials', {
          attemptsRemaining: after.attemptsRemaining,
          banned: after.banned,
          retryAfterSeconds: after.retryAfterSeconds,
        });
      }

      rateLimiter.clear(ip);
      const created = auth.createSession('user');
      res.cookie(USER_COOKIE_NAME, created.token, cookieOptions(config));
      audit.record('user_login', { ip, meta: { expiresAt: created.record.expiresAt, mode } });
      res.json({ authenticated: true, expiresAt: created.record.expiresAt, mustChangePassword: settings.get().mustChangePassword });
    }),
  );

  app.post(
    '/api/auth/logout',
    asyncHandler(async (req, res) => {
      const token = typeof req.cookies[USER_COOKIE_NAME] === 'string' ? req.cookies[USER_COOKIE_NAME] : undefined;
      auth.revokeToken(token, 'user');
      res.clearCookie(USER_COOKIE_NAME, { path: '/' });
      res.json({ authenticated: false });
    }),
  );

  app.get('/api/me', (req, res, next) => {
    const token = typeof req.cookies[USER_COOKIE_NAME] === 'string' ? req.cookies[USER_COOKIE_NAME] : undefined;
    const record = auth.validateToken(token, 'user');
    if (!record) {
      next(new HttpError(401, 'unauthorized', 'Login required'));
      return;
    }
    res.json({ authenticated: true, expiresAt: record.expiresAt });
  });

  // End users may see enabled node names/addresses, but never credentials.
  app.get(
    '/api/nodes',
    requireUserAuth,
    asyncHandler(async (_req, res) => {
      res.json({ nodes: nodes.listPublic().filter(node => node.enabled) });
    }),
  );

  app.get(
    '/api/session',
    requireUserAuth,
    asyncHandler(async (_req, res) => {
      const ownerHash = String(res.locals.ownerHash);
      sessions.sweep();
      const session = sessions.getActiveCurrentForOwner(ownerHash) ?? sessions.getCurrentForOwner(ownerHash);
      res.json({ session: session ? sessions.toPublic(session) : null });
    }),
  );

  app.post(
    '/api/session',
    requireUserAuth,
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
    requireUserAuth,
    asyncHandler(async (req, res) => {
      const session = sessions.touchCurrentForOwner(String(res.locals.ownerHash), clientIp(req));
      if (!session) throw new HttpError(404, 'session_not_found', 'No active session');
      res.json({ session: sessions.toPublic(session) });
    }),
  );

  app.post(
    '/api/session/revoke',
    requireUserAuth,
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
      templateDir: options.templateDir,
    });
    return { body: kind === 'crx' ? artifacts.crx : artifacts.zip, session };
  }

  app.get(
    '/api/session/extension.crx',
    requireUserAuth,
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
    requireUserAuth,
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

  // ------------------------------------------------------------ proxy gateway
  // In `server` proxy mode the extension points Chrome at this very port, so
  // the same listener must also speak HTTP proxy and CONNECT. Node credentials
  // never leave the server: the client only presents its one-time token.
  const gateway = new ProxyGateway({ config, audit, nodes, sessions, auth, rateLimiter, settings });
  const realm = 'RedProxy';

  // Absolute-form HTTP proxy requests (http://host/path) arrive as normal
  // Express requests, so they are handled here before the static catch-all.
  app.use((req, res, next) => {
    if (!config.proxyEnabled || req.method === 'CONNECT') {
      next();
      return;
    }
    if (!/^https?:\/\//i.test(req.url || '')) {
      next();
      return;
    }
    const decision = gateway.authenticate(req.header('proxy-authorization'), realm);
    if (!decision.ok) {
      res.setHeader('Proxy-Authenticate', decision.challenge);
      res.writeHead(407, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Proxy authentication required');
      return;
    }
    audit.record('proxy_request', {
      sessionId: decision.sessionId,
      nodeId: decision.node.id,
      ip: clientIp(req),
      meta: { method: req.method, target: req.url },
    });
    gateway.handleHttpRequest(req, res, decision.node);
  });

  app.use('/api', (_req, _res, next) => {
    next(new HttpError(404, 'api_not_found', 'API route not found'));
  });

  app.get('*', (req, res, next) => {
    serveSiteAsset(req, res, next, { site: 'user', publicDir: path.join(options.publicDir, '..') });
  });

  app.use(errorHandler());

  return { app, gateway, proxyRealm: realm };
}
