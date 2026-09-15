export type ProxyScheme = 'http' | 'https' | 'socks5';

export interface NodeRecord {
  id: string;
  name: string;
  scheme: ProxyScheme;
  host: string;
  port: number;
  username: string | null;
  password: string | null;
  enabled: boolean;
  createdAt: number;
}

export interface PublicNode {
  id: string;
  name: string;
  scheme: ProxyScheme;
  host: string;
  port: number;
  enabled: boolean;
  hasAuth: boolean;
}

export interface ExtensionNodeConfig {
  id: string;
  name: string;
  scheme: ProxyScheme;
  host: string;
  port: number;
  username: string | null;
  password: string | null;
}

export interface SessionRecord {
  id: string;
  ownerHash: string;
  deviceId: string;
  nodeId: string;
  extensionTokenHash: string | null;
  extensionTokenNonce: string;
  extensionTokenIssuedAt: number | null;
  createdAt: number;
  expiresAt: number;
  lastHeartbeatAt: number;
  revoked: boolean;
  revokedAt: number | null;
  revokedReason: string | null;
  ip: string;
  userAgent: string;
}

export interface PublicSession {
  id: string;
  deviceId: string;
  nodeId: string;
  nodeName: string;
  createdAt: number;
  expiresAt: number;
  lastHeartbeatAt: number;
  revoked: boolean;
  revokedAt: number | null;
  revokedReason: string | null;
  state: 'active' | 'revoked' | 'expired' | 'idle';
  remainingSeconds: number;
}

export interface AuthSessionRecord {
  tokenHash: string;
  createdAt: number;
  expiresAt: number;
  lastSeenAt: number;
}

export interface AuditEvent {
  id: number;
  at: number;
  type: string;
  sessionId?: string;
  deviceId?: string;
  nodeId?: string;
  reason?: string;
  ip?: string;
  meta?: Record<string, unknown>;
}

export interface ExtensionRuntimeConfig {
  serverUrl: string;
  extensionToken: string;
  sessionId: string;
  deviceId: string;
  expiresAt: number;
  generatedAt: number;
  heartbeatIntervalSeconds: number;
  idleSeconds: number;
  node: ExtensionNodeConfig;
}

export interface AppConfig {
  nodeEnv: string;
  port: number;
  publicBaseUrl: string;
  dataDir: string;
  crxPrivateKeyPath: string;
  sessionTtlSeconds: number;
  sessionIdleSeconds: number;
  maxConcurrentDevices: number;
  cookieSecure: boolean;
  authSessionTtlSeconds: number;
  loginMaxAttempts: number;
  loginWindowSeconds: number;
  crxKeyBits: number;
  trustProxy: boolean;
  allowInsecureHttp: boolean;
  adminTotpSecret: string | null;
}
