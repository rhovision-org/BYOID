#!/usr/bin/env node
// Deploy the BYOID REV proof registry to one writable rholo network.
//
// Usage:
//   RHOLO_URL=https://playground.rhobot.net node scripts/deploy-rev-registry.js
//   node scripts/deploy-rev-registry.js https://testnet.rhobot.net
//
// History is read-only; the script reports it and exits without writing.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { RholoClient } from '../src/rholo.js';
import { loadOrCreateDeployerKey } from '../src/store.js';
import { installedUri, readProgram, registryRefusal } from '../public/rev-registry.js';
import { REV_REGISTRY_URIS } from '../public/rev-registry-uris.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const contractPath = path.join(root, 'contracts', 'rev-proof-registry.rho');
const deploymentsPath = path.join(root, 'contracts', 'deployments.json');
const urisPath = path.join(root, 'public', 'rev-registry-uris.js');
// A valid REV address that no one publishes for, used only to probe.
const PROBE_ADDRESS = '1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g';
const url = String(
  process.argv[2] || process.env.RHOLO_URL || 'https://playground.rhobot.net',
).replace(/\/+$/, '');

const deployer = await loadOrCreateDeployerKey(
  path.join(root, 'data', 'deployer-key.json'),
  process.env.RHOLO_DEPLOYER_PRIVATE_KEY || null,
);
const client = new RholoClient({
  url,
  faucet: true,
  deployerKey: deployer,
  needsFaucet: true,
  phloLimit: 5_000_000,
  phloPrice: 1,
  deployWaitMs: 90_000,
  logger: console,
});

// Ask the recorded registry for a card that does not exist. A healthy v2
// registry answers {"ok": true, "card": Nil}; anything else means reinstall.
async function probe(uri) {
  if (!uri) return false;
  try {
    const submitted = await client.submitDeploy(readProgram(uri, PROBE_ADDRESS));
    const executed = await client.waitForDeploy(submitted.deployId, { timeoutMs: 30_000 });
    if (executed.state !== 'success') return false;
    return !registryRefusal(executed.result) && JSON.stringify(executed.result).includes('ok');
  } catch (error) {
    console.warn(`[registry] probe failed: ${error.message}`);
    return false;
  }
}

const network = await client.network().catch(() => null);
const capabilities = await client.getCapabilities().catch(() => null);
if (capabilities && capabilities.faucet === false && capabilities.proposeOnDeploy === false) {
  console.log(
    `[registry] ${url} (${network?.networkId || 'unknown'}) is read-only; no contract deployed.`,
  );
  process.exit(0);
}

console.log(
  `[registry] ${url} network=${network?.networkId || 'unknown'} shard=${network?.shardId || 'unknown'}`,
);
let status = 'existing';
let deployId = null;
let blockNumber = null;
let error = null;
let uri = REV_REGISTRY_URIS[url] || null;
if (await probe(uri)) {
  console.log(`[registry] v2 registry already answers at ${uri}`);
} else {
  const source = fs.readFileSync(contractPath, 'utf8');
  console.log(`[registry] installing ${source.length} byte Rholang contract…`);
  try {
    const submitted = await client.submitDeploy(source);
    deployId = submitted.deployId;
    const executed = await client.waitForDeploy(submitted.deployId);
    if (executed.state !== 'success' || !executed.block) {
      throw new Error(`contract deploy did not succeed: ${executed.error || executed.state}`);
    }
    blockNumber = executed.block.blockNumber ?? null;
    uri = installedUri(executed.result);
    if (!uri) throw new Error('the install deploy did not answer a registry URI');
    if (!(await probe(uri))) {
      throw new Error(`contract installed at ${uri} but the probe did not answer`);
    }
    status = 'deployed';
    console.log(`[registry] installed at ${uri} in block ${blockNumber}`);
  } catch (caught) {
    status = 'unavailable';
    error = caught.message;
    uri = null;
    console.warn(`[registry] contract unavailable on this network: ${error}`);
  }
}

if (uri) {
  const uris = { ...REV_REGISTRY_URIS, [url]: uri };
  const body = JSON.stringify(uris, null, 2);
  const text = fs.readFileSync(urisPath, 'utf8');
  fs.writeFileSync(
    urisPath,
    text.replace(/export const REV_REGISTRY_URIS = [\s\S]*?;\n/, `export const REV_REGISTRY_URIS = ${body};\n`),
  );
  console.log(`[registry] wrote ${path.relative(root, urisPath)}`);
}

const existing = fs.existsSync(deploymentsPath)
  ? JSON.parse(fs.readFileSync(deploymentsPath, 'utf8'))
  : {};
const previous = existing[url] || {};
existing[url] = {
  ...previous,
  url,
  contract: 'contracts/rev-proof-registry.rho',
  version: 2,
  uri: uri || null,
  status,
  error,
  deployId: deployId || previous.deployId || null,
  blockNumber: blockNumber ?? previous.blockNumber ?? null,
  networkId: network?.networkId || previous.networkId || null,
  shardId: network?.shardId || previous.shardId || null,
  checkedAt: new Date().toISOString(),
};
fs.mkdirSync(path.dirname(deploymentsPath), { recursive: true });
fs.writeFileSync(deploymentsPath, `${JSON.stringify(existing, null, 2)}\n`);
console.log(`[registry] wrote ${path.relative(root, deploymentsPath)}`);
