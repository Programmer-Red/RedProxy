export type ProxyScheme = 'http' | 'https' | 'socks4' | 'socks5';
export type NodeKind = 'proxy' | 'xray';
export type XrayProtocol = 'vless' | 'vmess' | 'trojan' | 'shadowsocks';
export type AuthMode = 'totp' | 'totp_password';
export type AuthRealm = 'user' | 'admin';

export interface XraySettings {
  protocol: XrayProtocol;
  uuid?: string | null;
  alterId?: number | null;
  password?: string | null;
  method?: string | null;
  flow?: string | null;
  network?: 'tcp' | 'ws' | 'grpc' | 'http' | 'kcp' | 'quic' | 'xhttp' | null;
  security?: 'none' | 'tls' | 'reality' | null;
  sni?: string | null;
  fingerprint?: string | null;
  publicKey?: string | null;
  shortId?: string | null;
  spiderX?: string | null;
  host?: string | null;
  path?: string | null;
  serviceName?: string | null;
  allowInsecure?: boolean | null;
}

export interface NodeRecord {
  id: string;
  name: string;
  kind: NodeKind;
  scheme: ProxyScheme;
  host: string;
  port: number;
  username: string | null;
  password: string | null;
  enabled: boolean;
  createdAt: number;
  /** Present for kind === 'xray'. */
  xray?: XraySettings;
  /** Local inbound that the browser extension connects to for Xray nodes. */
  localScheme?: ProxyScheme;
  localHost?: string;
  localPort?: number;
  source?: string;
}

export interface PublicNode {
  id: string;
  name: string;
  kind: NodeKind;
  scheme: ProxyScheme;
  host: string;
  port: number;
  enabled: boolean;
  hasAuth: boolean;
  xray?: Omit<XraySettings, 'password'>;
  localScheme?: ProxyScheme;
  localHost?: string;
  localPort?: number;
  source?: string;
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
  /** Single-use enrollment token embedded into the CRX. */
  enrollmentTokenHash: string | null;
  enrollmentTokenExpiresAt: number | null;
  /** Access token obtained by enrolling the extension. */
  accessTokenHash: string | null;
  /** Previous access token, accepted only during a short rotation grace window. */
  previousAccessTokenHash: string | null;
  previousAccessTokenValidUntil: number | null;
  tokenNonce: string;
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
  enrolled: boolean;
  revoked: boolean;
  revokedAt: number | null;
  revokedReason: string | null;
  state: 'active' | 'revoked' | 'expired' | 'idle' | 'pending';
  remainingSeconds: number;
  ip: string;
}

export interface AuthSessionRecord {
  tokenHash: string;
  realm: AuthRealm;
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
  enrollmentExpiresAt: number;
  idleSeconds: number;
  node: ExtensionNodeConfig;
}

export interface AdminSettings {
  authMode: AuthMode;
  totpSecretBase32: string;
  passwordHash: string | null;
  passwordSalt: string | null;
  passwordUpdatedAt: number | null;
  createdAt: number;
  updatedAt: number;
}

export interface AppConfig {
  nodeEnv: string;
  host: string;
  port: number;
  adminEnabled: boolean;
  adminHost: string;
  adminPort: number;
  publicBaseUrl: string;
  dataDir: string;
  crxPrivateKeyPath: string;
  sessionTtlSeconds: number;
  sessionIdleSeconds: number;
  enrollmentTtlSeconds: number;
  tokenGraceSeconds: number;
  maxConcurrentDevices: number;
  cookieSecure: boolean;
  authSessionTtlSeconds: number;
  loginMaxAttempts: number;
  loginWindowSeconds: number;
  loginBanSeconds: number;
  crxKeyBits: number;
  trustProxy: boolean;
  allowInsecureHttp: boolean;
  adminTotpSecret: string | null;
  authMode: AuthMode;
  staticDir: string | null;
  templateDir: string | null;
}
