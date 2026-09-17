import path from 'node:path';
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { readAsset } from '../assets';
import type { AppConfig } from '../types';

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

export function asyncHandler(handler: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

export function clientIp(req: Request): string {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

export function throwValidation(error: z.ZodError): never {
  throw new HttpError(400, 'invalid_request', 'Request validation failed', {
    issues: error.issues.map(issue => ({ path: issue.path.join('.'), message: issue.message })),
  });
}

export function cookieOptions(config: AppConfig) {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: config.cookieSecure,
    maxAge: config.authSessionTtlSeconds * 1000,
    path: '/',
  };
}

export function frontendContentType(filePath: string): string {
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

export interface SiteAssetOptions {
  /** e.g. "user" or "admin" - the folder under public/ and the embedded asset prefix */
  site: string;
  publicDir: string;
}

/** Serve a static site from disk when available, otherwise from embedded assets. */
export function serveSiteAsset(req: Request, res: Response, next: NextFunction, options: SiteAssetOptions): void {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    next();
    return;
  }
  let relative = req.path === '/' ? 'index.html' : req.path.replace(/^\//, '');
  if (!path.extname(relative)) relative = 'index.html';

  const key = `public/${options.site}/${relative}`;
  let content = readAsset(key, path.join(options.publicDir, options.site));
  let servedKey = relative;
  if (!content) {
    content = readAsset(`public/${options.site}/index.html`, path.join(options.publicDir, options.site));
    servedKey = 'index.html';
  }
  if (!content) {
    next();
    return;
  }
  res.setHeader('Content-Type', frontendContentType(servedKey));
  res.setHeader('Cache-Control', 'no-cache');
  res.send(content);
}

export function notFoundHandler(code: string, message: string) {
  return (_req: Request, _res: Response, next: NextFunction): void => {
    next(new HttpError(404, code, message));
  };
}

export function errorHandler() {
  return (error: unknown, _req: Request, res: Response, _next: NextFunction): void => {
    if (error instanceof HttpError) {
      res.status(error.status).json({ error: error.code, message: error.message, details: error.details });
      return;
    }
    const message = error instanceof Error ? error.message : 'Unexpected server error';
    console.error('[RedProxy] unhandled error:', error);
    res.status(500).json({ error: 'internal_error', message });
  };
}

/**
 * Extension service workers run with origin `chrome-extension://<id>` (or the
 * `moz-extension://` equivalent). When the manifest host_permissions are not
 * enough (for example an older generated CRX), the browser still sends a CORS
 * preflight for our Bearer-token heartbeat. This middleware answers that
 * preflight and echoes the origin so the call is not blocked.
 */
export function extensionCors(req: Request, res: Response, next: NextFunction): void {
  const origin = req.header('origin');
  if (origin && /^(chrome|moz|safari-web)-extension:\/\//i.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
  }
  next();
}
