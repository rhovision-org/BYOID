import http from 'node:http';
import path from 'node:path';

import { config, providerConfig } from './config.js';
import { ensureDir, loadOrCreateAgentKey, loadOrCreateDeployerKey } from './store.js';
import { RholoClient, RholoError } from './rholo.js';
import { AnchorError, AnchorService } from './anchor.js';
import { Agent } from './agent.js';
import { ANCHOR_STEPS, JobStore } from './jobs.js';
import {
  SessionStore,
  ensureSession,
  readSession,
  sameState,
} from './sessions.js';
import {
  HttpError,
  RateLimiter,
  Router,
  clientIp,
  readBody,
  readJsonBody,
  redirect,
  securityHeaders,
  sendJson,
  sendText,
  serveStatic,
} from './http.js';
import {
  PROVIDER_CATALOG,
  PROVIDER_IDS,
  buildAuthorizationUrl,
  demoProfile,
  exchangeCode,
  fetchProfile,
  getProvider,
  publicProviderInfo,
} from './providers.js';
import {
  base64url,
  pkceChallenge,
  randomBase64Url,
  sha256B64url,
  utf8,
} from './crypto.js';
import {
  anchorName,
  isDid,
  isRevAddress,
  revAnchorName,
  shortId,
  verifyCredential,
  verifyPresentation,
} from '../public/shared.js';

const log = {
  info: (...args) => console.log(...args),
  warn: (...args) => console.warn(...args),
  error: (...args) => console.error(...args),
};

const secureCookies = config.publicUrl.startsWith('https://');

await ensureDir(config.dataDir);
const deployer = await loadOrCreateDeployerKey(
  path.join(config.dataDir, 'deployer-key.json'),
  config.chain.rholo.deployerPrivateKey,
);
const agentKey = await loadOrCreateAgentKey(path.join(config.dataDir, 'agent-key.json'));

const client = new RholoClient({
  url: config.chain.rholo.url,
  shardId: config.chain.rholo.shardId,
  faucet: config.chain.rholo.faucet,
  deployerKey: deployer,
  needsFaucet: !config.chain.rholo.deployerPrivateKey,
  timeoutMs: config.chain.rholo.timeoutMs,
  deployWaitMs: config.chain.rholo.deployWaitMs,
  phloLimit: config.chain.rholo.phloLimit,
  phloPrice: config.chain.rholo.phloPrice,
  logger: log,
});

const agent = new Agent({
  key: agentKey,
  client,
  agentName: config.chain.agentName,
  enabled: config.chain.writes,
});
const anchors = new AnchorService({ client });
const jobs = new JobStore();
const sessions = new SessionStore({ ttlMs: config.sessionTtlMs });
const anchorLimiter = new RateLimiter({ max: config.rateLimit.anchorPerMinute });
const demoLimiter = new RateLimiter({ max: config.rateLimit.demoPerMinute });

const router = new Router();

// ── helpers ─────────────────────────────────────────────────────────────────

function providerList() {
  return PROVIDER_IDS.map((id) => {
    const provider = PROVIDER_CATALOG[id];
    const cfg = providerConfig(id);
    return publicProviderInfo(provider, cfg.configured, cfg.mode, cfg.redirectUri);
  });
}

function sessionView(session) {
  if (!session) return { hasSession: false, did: null, pendingLink: null };
  if (session.pendingLink) {
    const age = Date.now() - Date.parse(session.pendingLink.linkedAt || 0);
    if (!Number.isFinite(age) || age > 10 * 60 * 1000) delete session.pendingLink;
  }
  return {
    hasSession: true,
    did: session.did || null,
    pendingLink: session.pendingLink || null,
  };
}

function oauthFailure(res, message) {
  const safe = String(message || 'OAuth failed').slice(0, 240);
  log.warn(`[oauth] ${safe}`);
  redirect(res, `/?oauth_error=${encodeURIComponent(safe)}`);
}

function requireDid(value) {
  if (!isDid(value)) {
    throw new HttpError(400, 'invalid-did', 'a valid did:byoid identifier is required');
  }
  return value;
}

function requireRevAddress(value) {
  if (!isRevAddress(value)) {
    throw new HttpError(400, 'invalid-rev-address', 'a valid REV address is required');
  }
  return String(value).trim();
}

async function readRevProofCards(address) {
  const name = revAnchorName(address);
  const read = await client.readName(name);
  const cards = [];
  const invalid = [];
  for (const value of read.values) {
    try {
      cards.push(JSON.parse(Buffer.from(value, 'base64url').toString('utf8')));
    } catch {
      invalid.push(String(value).slice(0, 120));
    }
  }
  return {
    address,
    name,
    values: read.values.length,
    cards,
    invalid,
    block: read.block,
  };
}

async function publishRevProofCard(address, card) {
  if (!config.chain.writes) {
    throw new HttpError(409, 'chain-writes-disabled', 'chain writes are disabled');
  }
  if (!card || typeof card !== 'object' || card.revAddress !== address) {
    throw new HttpError(400, 'invalid-proof-card', 'proof card does not match the REV address');
  }
  const value = base64url(utf8(JSON.stringify(card)));
  if (value.length > 19_000) {
    throw new HttpError(413, 'proof-card-too-large', 'proof card is too large');
  }
  const name = revAnchorName(address);
  const resultName = `byoid:rev:result:${randomBase64Url(8)}`;
  const term =
    `@"byoid:rev:registry"!("publish", "${address}", "${value}", "${resultName}") | ` +
    `@"${name}"!("${value}")`;
  const submittedAt = new Date().toISOString();
  const submitted = await client.submitDeploy(term);
  const executed = await client.waitForDeploy(submitted.deployId);
  if (executed.state !== 'success' || !executed.block) {
    throw new HttpError(
      502,
      'rev-proof-not-executed',
      `the REV proof deploy did not execute: ${executed.error || executed.state}`,
    );
  }
  const observed = await client.getDataAtName(name, executed.block.blockHash);
  if (!observed.values.includes(value)) {
    throw new HttpError(502, 'rev-proof-not-observed', 'the proof card was not observed at its name');
  }
  return {
    eventId: `rev:${address}`,
    eventType: 'byoid.rev.proofs',
    eventSeq: null,
    name,
    valueHash: sha256B64url(value),
    deployId: submitted.deployId,
    submittedAt,
    confirmedAt: new Date().toISOString(),
    blockHash: executed.block.blockHash,
    blockNumber: executed.block.blockNumber,
    preStateHash: executed.block.preStateHash || null,
    postStateHash: executed.block.postStateHash || null,
    term,
  };
}

function rateLimit(limiter, req, label) {
  const result = limiter.hit(clientIp(req));
  if (!result.ok) {
    throw new HttpError(429, 'rate-limited', `${label} rate limit reached; try again shortly`, {
      retryAfter: result.retryAfter,
    });
  }
}

let chainStatusCache = { at: 0, body: null };

async function getChainStatus() {
  if (chainStatusCache.body && Date.now() - chainStatusCache.at < 1200) {
    return chainStatusCache.body;
  }
  const [status, capabilities, latestBlock] = await Promise.allSettled([
    client.getStatus(),
    client.getCapabilities(),
    client.latestBlock(),
  ]);
  const errors = [];
  if (status.status === 'rejected') errors.push(`status: ${status.reason.message}`);
  if (capabilities.status === 'rejected') errors.push(`capabilities: ${capabilities.reason.message}`);
  if (latestBlock.status === 'rejected') errors.push(`latest block: ${latestBlock.reason.message}`);
  const body = {
    ok: status.status === 'fulfilled',
    url: config.chain.rholo.url,
    fetchedAt: new Date().toISOString(),
    status: status.status === 'fulfilled' ? status.value : null,
    capabilities: capabilities.status === 'fulfilled' ? capabilities.value : null,
    latestBlock: latestBlock.status === 'fulfilled' ? latestBlock.value : null,
    errors,
  };
  chainStatusCache = { at: Date.now(), body };
  return body;
}

function applyProgress(jobId, progress) {
  switch (progress.step) {
    case 'validating':
      jobs.setStep(jobId, 'validated', 'active');
      break;
    case 'validated':
      jobs.setStep(jobId, 'validated', 'done');
      break;
    case 'submitting':
      jobs.setStep(jobId, 'submitted', 'active');
      break;
    case 'submitted':
      jobs.setStep(jobId, 'submitted', 'done', progress.deployId ? shortId(progress.deployId, 12, 8) : '');
      jobs.setStep(jobId, 'executed', 'active');
      break;
    case 'executed':
      jobs.setStep(jobId, 'executed', 'done');
      jobs.setStep(jobId, 'included', 'active');
      break;
    case 'included':
      jobs.setStep(
        jobId,
        'included',
        'done',
        progress.block?.blockNumber !== undefined ? `block ${progress.block.blockNumber}` : '',
      );
      jobs.setStep(jobId, 'observed', 'active');
      break;
    case 'observed':
      jobs.setStep(jobId, 'observed', 'done');
      break;
    default:
      break;
  }
}

// ── app metadata ────────────────────────────────────────────────────────────

router.get('/api/config', async (req, res) => {
  sendJson(res, 200, {
    app: {
      name: 'BYOID',
      version: '0.1.0',
      description: 'Bring Your Own Identity — self-sovereign identifiers anchored on rholo.',
    },
    publicUrl: config.publicUrl,
    chain: {
      url: config.chain.rholo.url,
      shardId: config.chain.rholo.shardId,
      writes: config.chain.writes,
      anchorPrefix: config.chain.anchorPrefix,
      agentName: config.chain.agentName,
      faucet: config.chain.rholo.faucet,
      phloLimit: config.chain.rholo.phloLimit,
    },
    providers: providerList(),
    agent: agent.publicInfo(),
    limits: {
      anchorPerMinute: config.rateLimit.anchorPerMinute,
      maxEventBytes: 16 * 1024,
    },
    demoMode: config.oauth.demoMode,
  });
});

router.get('/api/chain/status', async (req, res) => {
  sendJson(res, 200, await getChainStatus());
});

router.get('/api/agent', async (req, res) => {
  if (config.chain.writes && agent.anchorStatus === 'idle') {
    agent.ensureAnchored().catch(() => {});
  }
  sendJson(res, 200, {
    ...agent.publicInfo(),
    chainWrites: config.chain.writes,
    agentName: config.chain.agentName,
  });
});

router.post('/api/agent/anchor', async (req, res) => {
  if (!config.chain.writes) {
    throw new HttpError(409, 'chain-writes-disabled', 'chain writes are disabled');
  }
  try {
    const anchor = await agent.ensureAnchored();
    sendJson(res, 200, { anchor, agent: agent.publicInfo() });
  } catch (error) {
    throw new HttpError(502, 'agent-anchor-failed', error.message);
  }
});

// ── REV proof cards ─────────────────────────────────────────────────────────

router.get('/api/rev/:address', async (req, res, { params }) => {
  const address = requireRevAddress(params.address);
  sendJson(res, 200, await readRevProofCards(address));
});

router.post('/api/rev/publish', async (req, res) => {
  rateLimit(anchorLimiter, req, 'REV proof publish');
  const body = await readJsonBody(req, config.maxBodyBytes);
  const address = requireRevAddress(body.address);
  sendJson(res, 200, await publishRevProofCard(address, body.card));
});

// ── DID resolution / anchoring ──────────────────────────────────────────────

router.get('/api/did/:did', async (req, res, { params, url }) => {
  const did = requireDid(params.did);
  const force = url.searchParams.get('force') === '1';
  const resolution = await anchors.resolve(did, { force });
  sendJson(res, 200, {
    ...resolution,
    anchorName: anchorName(did, config.chain.anchorPrefix),
    source: {
      node: config.chain.rholo.url,
      name: anchorName(did, config.chain.anchorPrefix),
      block: resolution.block || null,
    },
  });
});

router.post('/api/anchor', async (req, res) => {
  if (!config.chain.writes) {
    throw new HttpError(409, 'chain-writes-disabled', 'chain writes are disabled');
  }
  rateLimit(anchorLimiter, req, 'anchor');
  const body = await readJsonBody(req, config.maxBodyBytes);
  const did = requireDid(body.did);
  if (!body.event || typeof body.event !== 'object') {
    throw new HttpError(400, 'missing-event', 'an event object is required');
  }
  const inspection = await anchors.inspect(did, body.event, { force: true });
  if (inspection.alreadyAnchored) {
    sendJson(res, 200, {
      alreadyAnchored: true,
      resolution: inspection.resolution,
      message: 'this event is already in the canonical DID log',
    });
    return;
  }
  const job = jobs.create({ kind: 'anchor', did, event: body.event, steps: ANCHOR_STEPS });
  jobs.run(job.id, async () => {
    const result = await anchors.run(did, body.event, {
      onProgress: (progress) => applyProgress(job.id, progress),
    });
    if (result.alreadyAnchored) {
      return { receipt: null, resolution: result.resolution, alreadyAnchored: true };
    }
    return result;
  });
  sendJson(res, 202, {
    jobId: job.id,
    status: 'queued',
    poll: `/api/anchor/jobs/${job.id}`,
    steps: job.steps,
  });
});

router.get('/api/anchor/jobs/:id', async (req, res, { params }) => {
  const job = jobs.get(params.id);
  if (!job) throw new HttpError(404, 'job-not-found', 'anchor job not found');
  sendJson(res, 200, job);
});

// ── verification helpers (same code as the browser) ─────────────────────────

router.post('/api/verify', async (req, res) => {
  const body = await readJsonBody(req, config.maxBodyBytes * 4);
  if (body.presentation) {
    const result = await verifyPresentation({
      presentation: body.presentation,
      resolveDid: (did) => anchors.resolve(did, { force: true }),
      agentPublicJwk: agent.publicJwk,
      agentKid: agent.kid,
    });
    sendJson(res, 200, result);
    return;
  }
  if (body.credential) {
    const issuer = body.credential.issuer;
    requireDid(issuer);
    const resolution = await anchors.resolve(issuer, { force: true });
    const result = await verifyCredential({
      credential: body.credential,
      resolution,
      agentPublicJwk: agent.publicJwk,
      agentKid: agent.kid,
    });
    sendJson(res, 200, result);
    return;
  }
  throw new HttpError(400, 'missing-document', 'send { presentation } or { credential }');
});

// ── chain proxies ───────────────────────────────────────────────────────────

router.get('/api/chain/deploy/:deployId', async (req, res, { params }) => {
  const document = await client.getDeployStatus(params.deployId);
  sendJson(res, 200, document);
});

router.get('/api/chain/block/:hash', async (req, res, { params }) => {
  const document = await client.getBlock(params.hash);
  sendJson(res, 200, document);
});

// ── sessions / OAuth ────────────────────────────────────────────────────────

router.get('/api/session', async (req, res) => {
  const { session } = readSession(req, sessions);
  sendJson(res, 200, sessionView(session));
});

router.post('/api/session/consume-link', async (req, res) => {
  const { session } = readSession(req, sessions);
  if (!session?.pendingLink) {
    sendJson(res, 200, { link: null });
    return;
  }
  const link = session.pendingLink;
  delete session.pendingLink;
  session.updatedAt = Date.now();
  sendJson(res, 200, { link });
});

router.get('/auth/:provider/start', async (req, res, { params, url }) => {
  let provider;
  let cfg;
  try {
    provider = getProvider(params.provider);
    cfg = providerConfig(params.provider);
  } catch {
    throw new HttpError(404, 'unknown-provider', 'unknown identity provider');
  }
  if (cfg.mode === 'demo') {
    redirect(res, `/?connect=${provider.id}`);
    return;
  }
  if (cfg.mode === 'unconfigured') {
    redirect(
      res,
      `/?oauth_error=${encodeURIComponent(
        `${provider.name} is not configured. Add ${provider.env.clientId} and ${provider.env.clientSecret} to .env.`,
      )}`,
    );
    return;
  }
  const did = url.searchParams.get('did') || '';
  if (!isDid(did)) {
    redirect(
      res,
      `/?oauth_error=${encodeURIComponent('Create your BYOID identity before connecting an account.')}`,
    );
    return;
  }

  const { session } = ensureSession(req, res, sessions, { secure: secureCookies });
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(48);
  const nonce = randomBase64Url(32);
  session.did = did;
  session.oauth = {
    provider: provider.id,
    state,
    verifier,
    nonce,
    did,
    createdAt: new Date().toISOString(),
  };
  session.updatedAt = Date.now();

  const authUrl = buildAuthorizationUrl(provider, cfg, {
    state,
    codeChallenge: pkceChallenge(verifier),
    redirectUri: cfg.redirectUri,
    nonce,
  });
  log.info(`[oauth] ${provider.id}: redirecting to provider`);
  redirect(res, authUrl);
});

function oauthProvider(providerId) {
  try {
    return {
      provider: getProvider(providerId),
      cfg: providerConfig(providerId),
    };
  } catch {
    throw new HttpError(404, 'unknown-provider', 'unknown identity provider');
  }
}

async function completeOAuthCallback(req, res, provider, cfg, searchParams) {
  const { session } = readSession(req, sessions);
  if (!session?.oauth || session.oauth.provider !== provider.id) {
    oauthFailure(res, 'OAuth session expired or was started for a different provider.');
    return;
  }

  const providerError = searchParams.get('error');
  if (providerError) {
    const description = searchParams.get('error_description') || providerError;
    delete session.oauth;
    oauthFailure(res, `${provider.name} returned: ${description}`);
    return;
  }

  const state = searchParams.get('state') || '';
  if (!sameState(session.oauth.state, state)) {
    delete session.oauth;
    oauthFailure(res, 'OAuth state did not match. Start the connection again.');
    return;
  }

  const code = searchParams.get('code') || '';
  if (!code) {
    delete session.oauth;
    oauthFailure(res, 'The provider did not return an authorization code.');
    return;
  }

  try {
    const tokens = await exchangeCode(provider, cfg, {
      code,
      codeVerifier: session.oauth.verifier,
      redirectUri: cfg.redirectUri,
    });
    const profile = await fetchProfile(provider, {
      ...tokens,
      clientId: cfg.clientId,
      nonce: session.oauth.nonce,
      user: searchParams.get('user') || null,
    });
    const did = session.oauth.did;
    requireDid(did);
    const attestation = await agent.signAttestation(
      { ...profile, demo: false },
      did,
    );
    session.pendingLink = {
      provider: provider.id,
      did,
      profile,
      subjectHash: attestation.subjectHash,
      attestation: attestation.attestation,
      attestationHash: attestation.attestationHash,
      issuedAt: attestation.issuedAt,
      linkedAt: new Date().toISOString(),
      demo: false,
    };
    delete session.oauth;
    session.did = did;
    session.updatedAt = Date.now();
    log.info(`[oauth] ${provider.id}: profile verified; waiting for the wallet to anchor the link`);
    redirect(res, `/?linked=${provider.id}`);
  } catch (error) {
    delete session.oauth;
    oauthFailure(res, `${provider.name} sign-in failed: ${error.message}`);
  }
}

router.get('/auth/:provider/callback', async (req, res, { params, url }) => {
  const { provider, cfg } = oauthProvider(params.provider);
  await completeOAuthCallback(req, res, provider, cfg, url.searchParams);
});

// Apple can be configured for form_post. Keep this route so that mode works
// even though BYOID defaults to the query response mode.
router.post('/auth/:provider/callback', async (req, res, { params }) => {
  const { provider, cfg } = oauthProvider(params.provider);
  const body = await readBody(req, config.maxBodyBytes);
  const form = new URLSearchParams(body.toString('utf8'));
  await completeOAuthCallback(req, res, provider, cfg, form);
});

router.post('/api/demo/link', async (req, res) => {
  rateLimit(demoLimiter, req, 'demo link');
  const body = await readJsonBody(req, config.maxBodyBytes);
  let provider;
  let cfg;
  try {
    provider = getProvider(body.provider);
    cfg = providerConfig(body.provider);
  } catch {
    throw new HttpError(404, 'unknown-provider', 'unknown identity provider');
  }
  if (cfg.mode !== 'demo') {
    throw new HttpError(409, 'demo-disabled', `${provider.name} is configured for live OAuth`);
  }
  const did = requireDid(body.did);
  let profile;
  try {
    profile = demoProfile(provider.id, body.profileId);
  } catch (error) {
    throw new HttpError(400, 'unknown-demo-profile', error.message);
  }
  profile.demo = true;
  const attestation = await agent.signAttestation(profile, did);
  sendJson(res, 200, {
    link: {
      provider: provider.id,
      did,
      profile,
      subjectHash: attestation.subjectHash,
      attestation: attestation.attestation,
      attestationHash: attestation.attestationHash,
      issuedAt: attestation.issuedAt,
      linkedAt: new Date().toISOString(),
      demo: true,
    },
  });
});

router.get('/healthz', async (req, res) => {
  sendJson(res, 200, {
    ok: true,
    uptime: Math.round(process.uptime()),
    chainWrites: config.chain.writes,
    agentAnchor: agent.anchorStatus,
  });
});

// ── HTTP server ─────────────────────────────────────────────────────────────

async function handler(req, res) {
  securityHeaders(res);
  const started = Date.now();
  const base = `http://${req.headers.host || 'localhost'}`;
  const url = new URL(req.url || '/', base);
  res.on('finish', () => {
    log.info(`[http] ${req.method} ${url.pathname} ${res.statusCode} ${Date.now() - started}ms`);
  });

  try {
    const match = router.match(req.method, url.pathname);
    if (match?.handler) {
      await match.handler(req, res, { params: match.params, url });
      return;
    }
    if (match?.methodNotAllowed) {
      throw new HttpError(405, 'method-not-allowed', 'method not allowed');
    }
    if (req.method === 'GET' || req.method === 'HEAD') {
      if (await serveStatic(res, config.publicDir, url.pathname)) return;
    }
    throw new HttpError(404, 'not-found', 'not found');
  } catch (error) {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    if (error instanceof HttpError) {
      const headers = {};
      if (error.extra?.retryAfter) headers['retry-after'] = String(error.extra.retryAfter);
      sendJson(
        res,
        error.status,
        { error: { code: error.code, message: error.message }, ...error.extra },
        headers,
      );
      return;
    }
    if (error instanceof AnchorError) {
      sendJson(
        res,
        error.status,
        {
          error: { code: error.code, message: error.message },
          ...(error.resolution ? { resolution: error.resolution } : {}),
        },
      );
      return;
    }
    if (error instanceof RholoError) {
      sendJson(res, 502, {
        error: { code: error.code || 'rholo-error', message: error.message },
      });
      return;
    }
    log.error('[http] unhandled error', error);
    sendJson(res, 500, {
      error: { code: 'internal', message: 'internal server error' },
    });
  }
}

const server = http.createServer((req, res) => {
  handler(req, res).catch((error) => {
    log.error('[http] fatal handler error', error);
    if (!res.headersSent) sendText(res, 500, 'internal server error');
    else res.destroy();
  });
});

server.listen(config.port, config.host, () => {
  log.info('');
  log.info('  BYOID — Bring Your Own Identity');
  log.info(`  app        http://${config.host}:${config.port}`);
  log.info(`  rholo      ${config.chain.rholo.url} (writes: ${config.chain.writes})`);
  log.info(`  deploy key ${deployer.address} (${deployer.source})`);
  log.info(`  agent key  ${agent.fingerprint}`);
  log.info(
    `  providers  ${PROVIDER_IDS.map((id) => `${id}=${providerConfig(id).mode}`).join(' ')}`,
  );
  log.info('');
  client
    .network()
    .then((network) => {
      log.info(
        `[rholo] discovered ${network.networkId || 'unknown network'} shard ${network.shardId} at block ${network.latestBlockNumber}`,
      );
    })
    .catch((error) => log.warn(`[rholo] status probe failed: ${error.message}`));
  if (config.chain.writes) {
    agent
      .ensureAnchored()
      .then((anchor) => {
        if (anchor.status === 'existing') {
          log.info(`[agent] reusing existing key anchor at ${anchor.name}`);
        } else if (anchor.status === 'anchored') {
          log.info(
            `[agent] key anchor confirmed in block ${anchor.blockNumber} (${anchor.deployId?.slice(0, 16)}…)`,
          );
        }
      })
      .catch((error) => log.warn(`[agent] key anchor failed: ${error.message}`));
  }
});

function shutdown(signal) {
  log.info(`\n[byoid] ${signal} received, shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
