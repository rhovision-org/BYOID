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
import { randomBase64Url } from '../src/crypto.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const contractPath = path.join(root, 'contracts', 'rev-proof-registry.rho');
const deploymentsPath = path.join(root, 'contracts', 'deployments.json');
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

async function probe() {
  const resultName = `byoid:rev:probe:${randomBase64Url(8)}`;
  const term = `@"byoid:rev:registry"!("get", "__byoid_probe__", "x", "${resultName}")`;
  try {
    const submitted = await client.submitDeploy(term);
    const executed = await client.waitForDeploy(submitted.deployId, { timeoutMs: 30_000 });
    if (executed.state !== 'success') return false;
    const read = await client.readName(resultName);
    return read.values.length > 0;
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
if (await probe()) {
  console.log('[registry] contract already responds at byoid:rev:registry');
} else {
  const source = fs.readFileSync(contractPath, 'utf8');
  console.log(`[registry] deploying ${source.length} byte Rholang contract…`);
  try {
    const submitted = await client.submitDeploy(source);
    deployId = submitted.deployId;
    const executed = await client.waitForDeploy(submitted.deployId);
    if (executed.state !== 'success' || !executed.block) {
      throw new Error(`contract deploy did not succeed: ${executed.error || executed.state}`);
    }
    blockNumber = executed.block.blockNumber ?? null;
    if (!(await probe())) {
      throw new Error('contract deployed but the probe did not return a value');
    }
    status = 'deployed';
    console.log(`[registry] deployed in block ${blockNumber}`);
  } catch (caught) {
    status = 'unavailable';
    error = caught.message;
    console.warn(`[registry] contract unavailable on this network: ${error}`);
  }
}

const existing = fs.existsSync(deploymentsPath)
  ? JSON.parse(fs.readFileSync(deploymentsPath, 'utf8'))
  : {};
const previous = existing[url] || {};
existing[url] = {
  ...previous,
  url,
  contract: 'byoid:rev:registry',
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
