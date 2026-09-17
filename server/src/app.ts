import path from 'node:path';
import type { Express } from 'express';
import { AuditLog } from './audit';
import { AuthService, LoginRateLimiter } from './auth';
import { ensureDataDir, loadConfig } from './config';
import { NodeService } from './nodes';
import { SessionService } from './sessions';
import { SettingsService } from './settings';
import { createUserSite } from './http/userSite';
import { createAdminSite } from './http/adminSite';
import type { AppServices } from './services';
import type { AppConfig } from './types';

export { HttpError } from './http/common';
export { USER_COOKIE_NAME } from './http/userSite';
export { ADMIN_COOKIE_NAME } from './http/adminSite';
export type { AppServices } from './services';

export interface CreateAppOptions {
  config?: AppConfig;
  now?: () => number;
  totpSecret?: string;
  publicDir?: string;
  templateDir?: string;
}

export interface RedProxySites {
  userApp: Express;
  adminApp: Express | null;
  services: AppServices;
  config: AppConfig;
}

/**
 * Build the two independent RedProxy sites:
 *   - userApp:  end-user portal (TOTP only), node selection + extension download
 *   - adminApp: separate administrator portal (TOTP, optionally + password)
 *
 * Each site has its own cookie name and its own server-side session realm, so
 * logging into one never grants access to the other.
 */
export function createApp(options: CreateAppOptions = {}): RedProxySites {
  const config = options.config ?? loadConfig();
  ensureDataDir(config);
  const now = options.now ?? (() => Date.now());
  const publicRoot = options.publicDir ?? config.staticDir ?? path.resolve(process.cwd(), 'public');
  const templateDir = options.templateDir ?? config.templateDir ?? path.resolve(process.cwd(), 'extension-template');

  const settings = new SettingsService(config, now, options.totpSecret ?? null);
  const audit = new AuditLog();
  const nodes = new NodeService(now);
  const sessions = new SessionService(config, nodes, audit, now);
  const auth = new AuthService(config, now);
  const rateLimiter = new LoginRateLimiter(config.loginMaxAttempts, config.loginWindowSeconds, config.loginBanSeconds, now);

  const services: AppServices = { config, audit, nodes, sessions, auth, rateLimiter, settings };

  const userApp = createUserSite({
    config,
    publicDir: path.join(publicRoot, 'user'),
    templateDir,
    audit,
    nodes,
    sessions,
    auth,
    rateLimiter,
    settings,
    now,
  });

  const adminApp = config.adminEnabled
    ? createAdminSite({ services, publicDir: path.join(publicRoot, 'admin'), templateDir })
    : null;

  setInterval(() => {
    try {
      sessions.sweep();
    } catch (error) {
      console.error('[RedProxy] session sweep failed:', error);
    }
  }, 10_000).unref();

  return { userApp, adminApp, services, config };
}
