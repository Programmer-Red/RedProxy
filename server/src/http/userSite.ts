import path from 'node:path';
import cookieParser from 'cookie-parser';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { AuditLog } from '../audit';
import { AuthService, LoginRateLimiter, extractBearerToken } from '../auth';
import { buildExtensionArtifacts, buildRuntimeConfig, sanitizeFileToken } from '../extension';
import { ConcurrentDeviceLimitError, InvalidExtensionTokenError, SessionService } from '../sessions';
import { SettingsService } from '../settings';
import type { AppConfig, SessionRecord } from '../types';
import { NodeService } from '../nodes';
import { asyncHandler, clientIp, cookieOptions, errorHandler, HttpError, serveSiteAsset, throwValidation } from './common';

export const USER_COOKIE_NAME = 'redproxy_user';

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
export function createUserSite(options: UserSiteOptions): express.Express {
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
    // The end-user portal always requires TOTP. The admin portal is where the
    // optional password layer is configured.
    res.json({ authMode: 'totp', passwordRequired: false });
  });

  app.post(
    '/api/auth/totp',
    asyncHandler(async (req, res) => {
      const parsed = z.object({ token: z.string().regex(/^\d{6}$/, 'token must be exactly 6 digits') }).safeParse(req.body);
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

      if (!settings.verifyUserTotp(parsed.data.token)) {
        const after = rateLimiter.recordFailure(ip);
        audit.record('user_login_failed', { ip, meta: { banned: after.banned } });
        throw new HttpError(401, 'invalid_totp', 'Invalid TOTP code', {
          attemptsRemaining: after.attemptsRemaining,
          banned: after.banned,
          retryAfterSeconds: after.retryAfterSeconds,
        });
      }

      rateLimiter.clear(ip);
      const created = auth.createSession('user');
      res.cookie(USER_COOKIE_NAME, created.token, cookieOptions(config));
      audit.record('user_login', { ip, meta: { expiresAt: created.record.expiresAt } });
      res.json({ authenticated: true, expiresAt: created.record.expiresAt });
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

  app.use('/api', (_req, _res, next) => {
    next(new HttpError(404, 'api_not_found', 'API route not found'));
  });

  app.get('*', (req, res, next) => {
    serveSiteAsset(req, res, next, { site: 'user', publicDir: path.join(options.publicDir, '..') });
  });

  app.use(errorHandler());

  return app;
}
