// Browser backend for the GitHub Pages build.
//
// Unlike the first static iteration, this one uses the real rholo playground:
// deploys are signed in the browser, submitted to https://playground.rhobot.net,
// and DID events are read back from the tuple-space name. The playground's CORS
// policy allows direct browser calls.
//
// What is still local/simulated:
//   * the OAuth provider profiles (demo mode);
//   * the demo link-agent key, which is intentionally embedded in this build;
//   * the phlo-payer key, generated per browser and funded by the dev faucet.

import {
  anchorName,
  b64url,
  canonicalize,
  didFromPublicJwk,
  eventId,
  EVENT_TYPES,
  hashField,
  isDid,
  providerSubjectHash,
  publicJwkOf,
  reduceEvents,
  sha256B64url,
  signEs256,
  utf8,
  validateEventShape,
  verifyCredential,
  verifyEventSignature,
  verifyPresentation,
} from './shared.js';
import { PROVIDER_CATALOG, PROVIDER_IDS } from './provider-catalog.js';
import { RholoWebClient, RholoWebError } from './rholo-web.js';

const LIVE_URL = 'https://playground.rhobot.net';
const WALLET_KEY = 'byoid.wallet.v1';
const AGENT_ISSUER = 'byoid:agent';
const AGENT_KID = 'byoid-agent-1';
const AGENT_NAME = 'byoid:agent:key';
const MAX_EVIDENCE_EVENTS = 200;

const ANCHOR_STEPS = [
  { key: 'validated', label: 'Signature and sequence checked' },
  { key: 'submitted', label: 'Deploy accepted by rholo' },
  { key: 'executed', label: 'Executed without error' },
  { key: 'included', label: 'Included in a block' },
  { key: 'observed', label: 'Observed at the DID anchor name' },
];

// Demo-only ES256 key for the identity-link agent. This key is public on
// purpose: the static build cannot keep an agent secret. It only signs demo
// OAuth attestations; the DID event chain is anchored with the wallet key.
const DEMO_AGENT_PRIVATE_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'ObbH-vfqegAXdiFRukPTqguT4Tjwy_IqPCsq_Jb-ol8',
  y: 'VcPGhDj78UbbwS6MAozOsknJnylyqERoYvqufvWnmNE',
  d: 'n81e-k_XgoB6AJtJqmV4c6gvWkFEAVq9L3L5E2hSIyw',
};
const DEMO_AGENT_PUBLIC_JWK = publicJwkOf(DEMO_AGENT_PRIVATE_JWK);

const isStaticHost =
  typeof window !== 'undefined' &&
  (window.BYOID_STATIC === true ||
    new URLSearchParams(window.location.search).get('static') === '1' ||
    window.location.protocol === 'file:' ||
    window.location.hostname.endsWith('github.io') ||
    window.location.pathname.includes('/BYOID/'));

export const STATIC_MODE = isStaticHost;

function basePath() {
  if (typeof window === 'undefined') return '/';
  const path = window.location.pathname;
  if (path.endsWith('/')) return path;
  return path.replace(/[^/]*$/, '') || '/';
}

function publicUrl() {
  if (typeof window === 'undefined') return 'http://localhost/';
  return `${window.location.origin}${basePath()}`.replace(/\/$/, '');
}

function randomB64url(length = 16) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return b64url(bytes);
}

function httpError(status, code, message, data = undefined) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  if (data !== undefined) error.data = data;
  return error;
}

function readWalletSnapshot() {
  try {
    const raw = localStorage.getItem(WALLET_KEY);
    if (!raw) return null;
    const wallet = JSON.parse(raw);
    return wallet && isDid(wallet.did) ? wallet : null;
  } catch {
    return null;
  }
}

function walletEvents(wallet) {
  if (!wallet) return [];
  const events = [];
  if (wallet.createEvent && (wallet.createReceipt || wallet.createAnchored)) {
    events.push(wallet.createEvent);
  }
  for (const link of wallet.links || []) {
    if (link.event && (link.receipt || link.anchored)) events.push(link.event);
  }
  for (const credential of wallet.credentials || []) {
    if (credential.revokeEvent && (credential.revokeReceipt || credential.revokedOnChain)) {
      events.push(credential.revokeEvent);
    }
  }
  return events;
}

async function agentInfo() {
  const fingerprint = `sha256:${await sha256B64url(canonicalize(DEMO_AGENT_PUBLIC_JWK))}`;
  return {
    issuer: AGENT_ISSUER,
    kid: AGENT_KID,
    publicJwk: DEMO_AGENT_PUBLIC_JWK,
    fingerprint,
    createdAt: '2026-11-08T00:00:00.000Z',
    role: 'demo identity-link agent (static build)',
    chainAnchor: {
      status: 'demo',
      name: AGENT_NAME,
      note: 'Demo link-agent key is embedded in the static build; DID events are anchored live on rholo.',
    },
  };
}

function publicProviders() {
  return PROVIDER_IDS.map((id) => {
    const provider = PROVIDER_CATALOG[id];
    return {
      id: provider.id,
      name: provider.name,
      kind: provider.kind,
      description: provider.description,
      scopes: provider.scopes,
      docsUrl: provider.docsUrl,
      configure: {
        clientIdEnv: provider.env.clientId,
        clientSecretEnv: provider.env.clientSecret,
        redirectUri: `${publicUrl()}/auth/${provider.id}/callback`,
      },
      mode: 'demo',
      configured: false,
      demoProfiles: provider.demoProfiles.map((profile) => ({
        id: profile.id,
        label: profile.label,
        handle: profile.handle,
        email: profile.email,
      })),
    };
  });
}

async function config() {
  return {
    app: {
      name: 'BYOID',
      version: '0.2.0-static',
      description: 'Bring Your Own Identity — browser wallet anchored live on the rholo playground.',
    },
    static: true,
    publicUrl: publicUrl(),
    chain: {
      url: LIVE_URL,
      shardId: null,
      writes: true,
      live: true,
      simulated: false,
      anchorPrefix: 'byoid',
      agentName: AGENT_NAME,
      faucet: true,
      phloLimit: 1_000_000,
    },
    providers: publicProviders(),
    agent: await agentInfo(),
    limits: { anchorPerMinute: 0, maxEventBytes: 16 * 1024 },
    demoMode: true,
  };
}

function createJobs() {
  const jobs = new Map();
  let sequence = 0;
  return {
    create({ did, event, steps = ANCHOR_STEPS }) {
      const now = new Date().toISOString();
      const job = {
        id: `web-${++sequence}-${randomB64url(8)}`,
        kind: 'anchor',
        did,
        eventId: event?.id || null,
        eventSeq: event?.seq || null,
        eventType: event?.type || null,
        status: 'queued',
        steps: steps.map((step) => ({ ...step, status: 'pending', detail: '' })),
        createdAt: now,
        updatedAt: now,
        error: null,
        receipt: null,
        resolution: null,
      };
      jobs.set(job.id, job);
      return job;
    },
    get(id) {
      return jobs.get(id) || null;
    },
    setStep(id, key, status, detail = '') {
      const job = jobs.get(id);
      if (!job) return null;
      const step = job.steps.find((candidate) => candidate.key === key);
      if (step) {
        step.status = status;
        if (detail) step.detail = detail;
      }
      job.updatedAt = new Date().toISOString();
      return job;
    },
    fail(id, error) {
      const job = jobs.get(id);
      if (!job) return null;
      const active = job.steps.find((step) => step.status === 'active');
      if (active) active.status = 'failed';
      job.status = 'error';
      job.error = {
        code: error.code || 'anchor-failed',
        message: error.message || String(error),
        ...(error.data?.resolution || error.resolution
          ? { resolution: error.data?.resolution || error.resolution }
          : {}),
      };
      job.updatedAt = new Date().toISOString();
      return job;
    },
    run(id, fn) {
      const job = jobs.get(id);
      if (!job) return null;
      job.status = 'running';
      Promise.resolve()
        .then(fn)
        .then((result) => {
          const current = jobs.get(id);
          if (!current) return;
          current.status = 'done';
          current.receipt = result?.receipt || null;
          current.resolution = result?.resolution || null;
          current.updatedAt = new Date().toISOString();
          for (const step of current.steps) step.status = 'done';
        })
        .catch((error) => this.fail(id, error));
      return job;
    },
  };
}

async function jwsSign(kid, payload) {
  const key = await crypto.subtle.importKey(
    'jwk',
    DEMO_AGENT_PRIVATE_JWK,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  const header = { alg: 'ES256', typ: 'JWT', kid };
  const signingInput = `${b64url(utf8(JSON.stringify(header)))}.${b64url(
    utf8(canonicalize(payload)),
  )}`;
  const signature = await signEs256(key, utf8(signingInput));
  return `${signingInput}.${b64url(signature)}`;
}

async function signAttestation(profile, did) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: AGENT_ISSUER,
    sub: did,
    aud: 'byoid.verifier',
    iat: now,
    jti: randomB64url(16),
    provider: profile.provider,
    providerSubjectHash: await providerSubjectHash(profile.provider, profile.subject),
    handleHash: profile.handle ? await hashField('handle', profile.handle) : null,
    emailHash: profile.email ? await hashField('email', profile.email) : null,
    emailVerified: Boolean(profile.emailVerified),
    nameHash: profile.name ? await hashField('name', profile.name) : null,
    avatarHash: profile.avatarUrl ? await hashField('avatarUrl', profile.avatarUrl) : null,
    demo: true,
  };
  const attestation = await jwsSign(AGENT_KID, payload);
  return {
    provider: profile.provider,
    subjectHash: payload.providerSubjectHash,
    attestation,
    attestationHash: await sha256B64url(attestation),
    issuedAt: new Date(now * 1000).toISOString(),
    payload,
  };
}

function demoProfile(providerId, profileId) {
  const provider = PROVIDER_CATALOG[providerId];
  if (!provider) throw httpError(404, 'unknown-provider', 'unknown identity provider');
  const profile = provider.demoProfiles.find((candidate) => candidate.id === profileId);
  if (!profile) throw httpError(400, 'unknown-demo-profile', 'unknown demo profile');
  return {
    provider: provider.id,
    subject: profile.subject,
    handle: profile.handle,
    name: profile.name,
    email: profile.email,
    emailVerified: profile.emailVerified,
    avatarUrl: profile.avatarUrl,
    demo: true,
  };
}

export function createStaticBackend({ getWallet = readWalletSnapshot } = {}) {
  const client = new RholoWebClient({
    url: LIVE_URL,
    faucet: true,
    logger: console,
  });
  const jobs = createJobs();
  const evidence = new Map();
  let chainStatusCache = { at: 0, body: null };

  const wallet = () => {
    try {
      return getWallet() || readWalletSnapshot();
    } catch {
      return readWalletSnapshot();
    }
  };

  function decorate(did, resolution, sourceKind = 'rholo') {
    const name = anchorName(did, 'byoid');
    return {
      ...resolution,
      anchorName: name,
      source: {
        node: LIVE_URL,
        name,
        block: resolution.block || null,
        live: sourceKind === 'rholo',
        evidence: sourceKind !== 'rholo',
      },
    };
  }

  async function resolve(did) {
    if (!isDid(did)) throw httpError(400, 'invalid-did', 'a valid did:byoid identifier is required');
    let chainError = null;
    let resolution = null;
    try {
      resolution = await client.resolveDid(did);
    } catch (error) {
      chainError = error;
    }
    if (resolution?.status?.valid) return decorate(did, resolution, 'rholo');

    const fallbackEvents = evidence.get(did);
    if (fallbackEvents?.length) {
      const fallback = await reduceEvents(did, fallbackEvents);
      if (fallback.status.valid) return decorate(did, fallback, 'evidence');
    }

    if (chainError) {
      throw httpError(
        502,
        'chain-unavailable',
        `could not read the rholo anchor: ${chainError.message}`,
      );
    }
    return decorate(did, resolution, 'rholo');
  }

  async function inspect(did, event) {
    if (!isDid(did)) throw httpError(400, 'invalid-did', 'a valid did:byoid identifier is required');
    try {
      validateEventShape(event);
    } catch (error) {
      throw httpError(400, 'invalid-event', error.message);
    }
    if (event.did !== did) {
      throw httpError(400, 'did-mismatch', 'event.did does not match the requested DID');
    }
    const expectedId = await eventId(event);
    if (event.id !== expectedId) {
      throw httpError(400, 'bad-event-id', 'event id is not the hash of its content');
    }

    if (event.type === EVENT_TYPES.CREATE) {
      const derived = await didFromPublicJwk(event.payload.publicKeyJwk);
      if (derived !== did) {
        throw httpError(400, 'did-key-mismatch', 'DID is not derived from the create event key');
      }
      if (!(await verifyEventSignature(event.payload.publicKeyJwk, event))) {
        throw httpError(400, 'bad-signature', 'create event signature does not verify');
      }
      const resolution = await resolve(did);
      if (resolution.status.valid) {
        if (resolution.createEvent?.id === event.id) {
          return { alreadyAnchored: true, resolution };
        }
        throw httpError(409, 'did-already-exists', 'this DID already has a create event on chain', {
          resolution,
        });
      }
      return { alreadyAnchored: false, resolution };
    }

    const resolution = await resolve(did);
    if (!resolution.status.valid) {
      throw httpError(404, 'did-not-found', 'no valid create event for this DID', { resolution });
    }
    if (resolution.deactivated) {
      throw httpError(409, 'did-deactivated', 'this DID has been deactivated', { resolution });
    }
    if (resolution.events.some((candidate) => candidate.id === event.id)) {
      return { alreadyAnchored: true, resolution };
    }
    if (event.seq !== resolution.status.latestSeq + 1) {
      throw httpError(
        409,
        'stale-sequence',
        `event seq ${event.seq} does not extend the chain tip (${resolution.status.latestSeq}); re-sign and retry`,
        { resolution },
      );
    }
    if (event.prev !== resolution.status.latestEventId) {
      throw httpError(
        409,
        'stale-sequence',
        'event prev does not point at the current chain tip; re-sign and retry',
        { resolution },
      );
    }
    if (!(await verifyEventSignature(resolution.publicKeyJwk, event))) {
      throw httpError(400, 'bad-signature', 'event signature does not verify with the DID key', {
        resolution,
      });
    }
    if (event.type === EVENT_TYPES.LINK && !PROVIDER_IDS.includes(event.payload.provider)) {
      throw httpError(
        400,
        'provider-not-supported',
        `unsupported identity provider: ${event.payload.provider}`,
      );
    }
    return { alreadyAnchored: false, resolution };
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
        jobs.setStep(
          jobId,
          'submitted',
          'done',
          progress.deployId ? `${progress.deployId.slice(0, 12)}…` : '',
        );
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

  function startJob(did, event) {
    const job = jobs.create({ did, event });
    jobs.run(job.id, async () => {
      applyProgress(job.id, { step: 'validating' });
      const inspection = await inspect(did, event);
      if (inspection.alreadyAnchored) {
        applyProgress(job.id, { step: 'validated' });
        return { alreadyAnchored: true, resolution: inspection.resolution };
      }
      applyProgress(job.id, { step: 'validated' });
      const receipt = await client.anchorEvent(did, event, {
        onProgress: (progress) => applyProgress(job.id, progress),
      });
      const resolution = await resolve(did);
      if (!resolution.events.some((candidate) => candidate.id === event.id)) {
        throw httpError(
          409,
          'anchor-not-in-chain',
          'the deploy executed but this event is not in the canonical DID log',
        );
      }
      return { receipt, resolution };
    });
    return job;
  }

  async function chainStatus() {
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
      static: true,
      live: true,
      url: LIVE_URL,
      fetchedAt: new Date().toISOString(),
      status: status.status === 'fulfilled' ? status.value : null,
      capabilities: capabilities.status === 'fulfilled' ? capabilities.value : null,
      latestBlock: latestBlock.status === 'fulfilled' ? latestBlock.value : null,
      errors,
    };
    chainStatusCache = { at: Date.now(), body };
    return body;
  }

  async function ingestEvidence(document) {
    const list = document?.byoidEvidence;
    if (!list) return 0;
    const entries = Array.isArray(list) ? list : [list];
    let added = 0;
    for (const entry of entries) {
      if (!entry || !isDid(entry.did) || !Array.isArray(entry.events)) continue;
      const existing = evidence.get(entry.did) || [];
      for (const event of entry.events) {
        if (!event || event.did !== entry.did) continue;
        if (existing.some((candidate) => candidate.id === event.id)) continue;
        existing.push(event);
        added += 1;
      }
      evidence.set(entry.did, existing.slice(-MAX_EVIDENCE_EVENTS));
    }
    return added;
  }

  function evidenceFor(did) {
    return walletEvents(wallet()).filter((event) => event.did === did);
  }

  async function request(path, { method = 'GET', body } = {}) {
    const url = new URL(path, window.location.origin);
    const pathname = url.pathname;
    const verb = String(method || 'GET').toUpperCase();
    try {
      if (verb === 'GET' && pathname === '/api/config') return await config();
      if (verb === 'GET' && pathname === '/api/chain/status') return await chainStatus();
      if (verb === 'GET' && pathname === '/api/agent') {
        return { ...(await agentInfo()), chainWrites: true, agentName: AGENT_NAME };
      }
      if (verb === 'POST' && pathname === '/api/agent/anchor') {
        const info = await agentInfo();
        return { anchor: info.chainAnchor, agent: info };
      }

      if (verb === 'GET' && pathname.startsWith('/api/did/')) {
        const did = decodeURIComponent(pathname.slice('/api/did/'.length));
        return await resolve(did);
      }

      if (verb === 'POST' && pathname === '/api/anchor') {
        const did = body?.did;
        if (!body?.event || typeof body.event !== 'object') {
          throw httpError(400, 'missing-event', 'an event object is required');
        }
        const job = startJob(did, body.event);
        return {
          jobId: job.id,
          status: 'queued',
          poll: `/api/anchor/jobs/${job.id}`,
          steps: job.steps,
          live: true,
        };
      }

      if (verb === 'GET' && pathname.startsWith('/api/anchor/jobs/')) {
        const id = decodeURIComponent(pathname.slice('/api/anchor/jobs/'.length));
        const job = jobs.get(id);
        if (!job) throw httpError(404, 'job-not-found', 'anchor job not found');
        return job;
      }

      if (verb === 'POST' && pathname === '/api/verify') {
        if (body?.presentation) {
          await ingestEvidence(body.presentation);
          return await verifyPresentation({
            presentation: body.presentation,
            resolveDid: (did) => resolve(did),
            agentPublicJwk: DEMO_AGENT_PUBLIC_JWK,
            agentKid: AGENT_KID,
          });
        }
        if (body?.credential) {
          await ingestEvidence(body.credential);
          const issuer = body.credential.issuer;
          if (!isDid(issuer)) {
            throw httpError(400, 'invalid-did', 'a valid did:byoid identifier is required');
          }
          const resolution = await resolve(issuer);
          return await verifyCredential({
            credential: body.credential,
            resolution,
            agentPublicJwk: DEMO_AGENT_PUBLIC_JWK,
            agentKid: AGENT_KID,
          });
        }
        throw httpError(400, 'missing-document', 'send { presentation } or { credential }');
      }

      if (verb === 'GET' && pathname.startsWith('/api/chain/deploy/')) {
        const deployId = decodeURIComponent(pathname.slice('/api/chain/deploy/'.length));
        return await client.getDeployStatus(deployId);
      }
      if (verb === 'GET' && pathname.startsWith('/api/chain/block/')) {
        const hash = decodeURIComponent(pathname.slice('/api/chain/block/'.length));
        return await client.getBlock(hash);
      }

      if (verb === 'GET' && pathname === '/api/session') {
        const current = wallet();
        return { hasSession: Boolean(current), did: current?.did || null, pendingLink: null };
      }
      if (verb === 'POST' && pathname === '/api/session/consume-link') {
        return { link: null };
      }

      if (verb === 'POST' && pathname === '/api/demo/link') {
        const did = body?.did;
        if (!isDid(did)) {
          throw httpError(400, 'invalid-did', 'a valid did:byoid identifier is required');
        }
        const profile = demoProfile(body?.provider, body?.profileId);
        const attestation = await signAttestation(profile, did);
        return {
          link: {
            provider: profile.provider,
            did,
            profile,
            subjectHash: attestation.subjectHash,
            attestation: attestation.attestation,
            attestationHash: attestation.attestationHash,
            issuedAt: attestation.issuedAt,
            linkedAt: new Date().toISOString(),
            demo: true,
          },
        };
      }

      throw httpError(404, 'not-found', `no static demo route for ${pathname}`);
    } catch (error) {
      if (error instanceof RholoWebError) {
        throw httpError(error.status || 502, error.code || 'rholo-error', error.message);
      }
      throw error;
    }
  }

  return {
    request,
    ingestEvidence,
    evidenceFor,
    publicJwk: DEMO_AGENT_PUBLIC_JWK,
    kid: AGENT_KID,
    issuer: AGENT_ISSUER,
    liveChain: true,
  };
}
