import 'dotenv/config';
import { createApp } from './app';
import { loadConfig } from './config';

const config = loadConfig();
const { app } = createApp({ config });

const server = app.listen(config.port, () => {
  console.log(`[RedProxy] listening on http://0.0.0.0:${config.port}`);
  console.log(`[RedProxy] public base URL: ${config.publicBaseUrl}`);
  console.log(`[RedProxy] max concurrent devices: ${config.maxConcurrentDevices}`);
  console.log(`[RedProxy] session TTL: ${config.sessionTtlSeconds}s, idle timeout: ${config.sessionIdleSeconds}s`);
  if (config.nodeEnv === 'production' && !config.publicBaseUrl.startsWith('https://') && !config.allowInsecureHttp) {
    console.warn('[RedProxy] WARNING: production is configured without HTTPS; extension downloads will be refused.');
  }
});

function shutdown(signal: string): void {
  console.log(`[RedProxy] received ${signal}, shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
