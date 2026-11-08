import fs from 'node:fs/promises';
import path from 'node:path';
import {
  generateAgentKey,
  generateDeployer,
  deployerFromPrivateKey,
  isValidPublicJwk,
} from './crypto.js';

export async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

export async function readJson(file, fallback = null) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw new Error(`Cannot read ${path.basename(file)}: ${error.message}`);
  }
}

/** Atomic JSON write with restrictive permissions by default. */
export async function writeJson(file, value, { mode = 0o600 } = {}) {
  await ensureDir(path.dirname(file));
  const temp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode });
  await fs.rename(temp, file);
  try {
    await fs.chmod(file, mode);
  } catch {
    // Best effort; some filesystems do not support chmod.
  }
}

export async function loadOrCreateDeployerKey(file, configuredPrivateKey) {
  if (configuredPrivateKey) {
    return { ...deployerFromPrivateKey(configuredPrivateKey), source: 'env' };
  }
  const stored = await readJson(file);
  if (stored?.privateKeyHex) {
    try {
      return { ...deployerFromPrivateKey(stored.privateKeyHex), source: 'file' };
    } catch {
      // Fall through and create a fresh key rather than starting with a bad one.
    }
  }
  const deployer = generateDeployer();
  await writeJson(file, {
    ...deployer,
    createdAt: new Date().toISOString(),
    note: 'Throwaway rholo playground deploy key. It pays phlo; it cannot sign as a BYOID user.',
  });
  return { ...deployer, source: 'generated' };
}

export async function loadOrCreateAgentKey(file) {
  const stored = await readJson(file);
  if (stored?.privateJwk && isValidPublicJwk(stored.publicJwk)) {
    return { ...stored, source: 'file' };
  }
  const generated = await generateAgentKey();
  const record = {
    ...generated,
    note: 'BYOID demo agent key. Signs identity-link attestations; never sent to the browser.',
  };
  await writeJson(file, record);
  return { ...record, source: 'generated' };
}
