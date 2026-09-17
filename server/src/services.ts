import { AuditLog } from './audit';
import { AuthService, LoginRateLimiter } from './auth';
import { NodeService } from './nodes';
import { SessionService } from './sessions';
import { SettingsService } from './settings';
import type { AppConfig } from './types';

export interface AppServices {
  config: AppConfig;
  audit: AuditLog;
  nodes: NodeService;
  sessions: SessionService;
  auth: AuthService;
  rateLimiter: LoginRateLimiter;
  settings: SettingsService;
}
