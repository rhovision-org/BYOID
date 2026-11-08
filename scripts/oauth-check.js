#!/usr/bin/env node
// Print live OAuth readiness without revealing any secret values.

import { config, providerConfig } from '../src/config.js';
import { PROVIDER_IDS, PROVIDER_CATALOG } from '../src/providers.js';

console.log(`PUBLIC_URL=${config.publicUrl}`);
console.log('');
let live = 0;
for (const id of PROVIDER_IDS) {
  const provider = PROVIDER_CATALOG[id];
  const cfg = providerConfig(id);
  if (cfg.mode === 'live') live += 1;
  console.log(`${provider.name.padEnd(10)} ${cfg.mode.padEnd(12)} ${cfg.redirectUri}`);
  if (cfg.mode !== 'live') {
    const missing = [];
    if (!cfg.clientId) missing.push(provider.env.clientId);
    if (id === 'apple') {
      if (!cfg.clientSecret && !cfg.applePrivateKey) missing.push(provider.env.privateKey);
      if (!cfg.clientSecret && !cfg.appleTeamId) missing.push(provider.env.teamId);
      if (!cfg.clientSecret && !cfg.appleKeyId) missing.push(provider.env.keyId);
    } else if (!cfg.clientSecret) {
      missing.push(provider.env.clientSecret);
    }
    if (missing.length) console.log(`  missing: ${missing.join(', ')}`);
    if (id === 'apple') {
      console.log('  note: APPLE_PRIVATE_KEY_PATH is also accepted for the .p8 key');
    }
  }
}
console.log('');
console.log(
  live === PROVIDER_IDS.length
    ? 'All providers are configured for live OAuth.'
    : `${live}/${PROVIDER_IDS.length} providers live; the rest fall back to demo mode.`,
);
if (live < PROVIDER_IDS.length) {
  console.log('See docs/oauth.md for registration steps and exact callback URLs.');
}
