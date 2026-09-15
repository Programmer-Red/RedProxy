import fs from 'node:fs';
import path from 'node:path';
import { EMBEDDED_ASSETS } from './generated/assets';

export function embeddedAsset(key: string): string | null {
  return Object.prototype.hasOwnProperty.call(EMBEDDED_ASSETS, key) ? EMBEDDED_ASSETS[key] ?? null : null;
}

export function readAsset(key: string, diskDir?: string | null): string | null {
  if (diskDir) {
    const candidate = path.join(diskDir, key.split('/').slice(1).join('/'));
    try {
      if (fs.existsSync(candidate)) return fs.readFileSync(candidate, 'utf8');
    } catch {
      // Fall through to the embedded asset.
    }
  }
  return embeddedAsset(key);
}

export function listEmbeddedAssets(): string[] {
  return Object.keys(EMBEDDED_ASSETS);
}
