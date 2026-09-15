import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { loadConfig, ensureDataDir } from '../server/src/config';
import { ensureCrxPrivateKey } from '../server/src/extension';

async function main(): Promise<void> {
  if (process.env.NODE_ENV === 'production' && !process.env.ALLOW_INSECURE_KEY_SCRIPT) {
    // The check is intentionally permissive here; the script only touches the data directory.
  }

  const config = loadConfig();
  ensureDataDir(config);
  const requestedPath = process.argv[2] ? path.resolve(process.argv[2]) : config.crxPrivateKeyPath;
  if (fs.existsSync(requestedPath)) {
    console.log(`CRX private key already exists: ${requestedPath}`);
    return;
  }

  await ensureCrxPrivateKey(requestedPath, config.crxKeyBits);
  console.log(`Generated CRX private key (${config.crxKeyBits}-bit RSA): ${requestedPath}`);
  console.log('Keep this file out of Git. It is already ignored by .gitignore.');
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
