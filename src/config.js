import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROVIDER_CATALOG, PROVIDER_IDS } from './providers.js';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Minimal .env loader: KEY=value, optional quotes, # comments. Existing env wins. */
function loadDotEnv(file) {
  if (!fs.existsSync(file)) return;
  const text = fs.readFileSync(file, 'utf8');
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim().replace(/^export\s+/, '');
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

function envString(name, fallback = '') {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : String(value);
}

function envBool(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(value);
}

function envInt(name, fallback) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
}

const rootDir = path.resolve(here, '..');
loadDotEnv(path.join(rootDir, '.env'));

const port = envInt('PORT', 3000);
const publicUrl = envString('PUBLIC_URL', `http://localhost:${port}`).replace(/\/+$/, '');
const demoMode = envString('OAUTH_DEMO', 'auto').toLowerCase();

const providers = {};
for (const id of PROVIDER_IDS) {
  const catalog = PROVIDER_CATALOG[id];
  const clientId = envString(catalog.env.clientId);
  const clientSecret = envString(catalog.env.clientSecret);
  const configured = Boolean(clientId && clientSecret);
  const mode = configured ? 'live' : demoMode === 'off' ? 'unconfigured' : 'demo';
  providers[id] = {
    id,
    clientId,
    clientSecret,
    configured,
    mode,
    redirectUri: `${publicUrl}/auth/${id}/callback`,
  };
}

export const config = {
  rootDir,
  publicDir: path.join(rootDir, 'public'),
  dataDir: path.join(rootDir, 'data'),
  host: envString('HOST', '127.0.0.1'),
  port,
  publicUrl,
  sessionTtlMs: 60 * 60 * 1000,
  maxBodyBytes: 64 * 1024,
  chain: {
    writes: envBool('CHAIN_WRITES', true),
    anchorPrefix: envString('ANCHOR_PREFIX', 'byoid'),
    agentName: `${envString('ANCHOR_PREFIX', 'byoid')}:agent:key`,
    rholo: {
      url: envString('RHOLO_URL', 'https://playground.rhobot.net').replace(/\/+$/, ''),
      shardId: envString('RHOLO_SHARD', '') || null,
      faucet: envBool('RHOLO_FAUCET', true),
      deployerPrivateKey: envString('RHOLO_DEPLOYER_PRIVATE_KEY', '') || null,
      timeoutMs: envInt('RHOLO_TIMEOUT_MS', 25000),
      deployWaitMs: envInt('RHOLO_DEPLOY_WAIT_MS', 40000),
      phloLimit: envInt('RHOLO_PHLO_LIMIT', 1_000_000),
      phloPrice: envInt('RHOLO_PHLO_PRICE', 1),
    },
  },
  oauth: {
    demoMode,
    providers,
  },
  rateLimit: {
    anchorPerMinute: envInt('ANCHOR_RATE_LIMIT', 30),
    demoPerMinute: envInt('DEMO_RATE_LIMIT', 30),
  },
};

export function providerConfig(providerId) {
  const cfg = config.oauth.providers[providerId];
  if (!cfg) throw new Error(`Unknown identity provider: ${providerId}`);
  return cfg;
}
