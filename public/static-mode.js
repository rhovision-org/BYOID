// Browser-only BYOID backend for static hosting (GitHub Pages).
//
// The GitHub Pages build has no Node process, so this module implements the
// small `/api/*` surface the UI needs. Everything is local to the browser:
//
//   * the demo link agent signs real ES256 attestations with a demo key that
//     is intentionally public in this repository;
//   * events are validated and hash-linked with the same code as the server;
//   * the "public name" is a localStorage bulletin board and anchoring is
//     simulated. The UI labels this mode clearly.
//
// It is deliberately not a substitute for the Node app: no OAuth secrets, no
// server-side wallet key custody, and no live rholo writes.

import {
  anchorName,
  b64url,
  canonicalize,
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

const CHAIN_KEY = 'byoid.static.chain.v1';
const WALLET_KEY = 'byoid.wallet.v1';
const AGENT_ISSUER = 'byoid:agent';
const AGENT_KID = 'byoid-agent-1';
const AGENT_NAME = 'byoid:agent:key';
const MAX_EVENTS_PER_DID = 200;

// Demo-only ES256 key for the identity-link agent. This key is public on
// purpose: anybody using the static demo can mint demo attestations. Never
// reuse it where an attestation is meant to prove a provider sign-in.
const DEMO_AGENT_PRIVATE_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'ObbH-vfqegAXdiFRukPTqguT4Tjwy_IqPCsq_Jb-ol8',
  y: 'VcPGhDj78UbbwS6MAozOsknJnylyqERoYvqufvWnmNE',
  d: 'n81e-k_XgoB6AJtJqmV4c6gvWkFEAVq9L3L5E2hSIyw',
};
const DEMO_AGENT_PUBLIC_JWK = publicJwkOf(DEMO_AGENT_PRIVATE_JWK);

const PROGRESS_STEPS = [
  { key: 'validated', label: 'Signature and sequence checked' },
  { key: 'submitted', label: 'Event accepted by the static demo' },
  { key: 'executed', label: 'Event applied to the demo log' },
  { key: 'included', label: 'Added to the demo block height' },
  { key: 'observed', label: 'Readable at the demo anchor name' },
];

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

function randomB64url(length = 32) {
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

function readStore() {
  try {
    const parsed = JSON.parse(localStorage.getItem(CHAIN_KEY) || '{}');
    return {
      blockHeight: Number.isInteger(parsed.blockHeight) ? parsed.blockHeight : 0,
      dids: parsed.dids && typeof parsed.dids === 'object' ? parsed.dids : {},
    };
  } catch {
    return { blockHeight: 0, dids: {} };
  }
}

function writeStore(store) {
  try {
    localStorage.setItem(CHAIN_KEY, JSON.stringify(store));
  } catch {
    // Storage can be disabled (private mode / quota). The demo still works
    // for the current page life; evidence is carried in presentations.
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

function collectEvents(did, wallet) {
  const store = readStore();
  const events = [...(store.dids[did] || [])];
  if (wallet?.did === did) {
    for (const event of walletEvents(wallet)) {
      if (!events.some((candidate) => candidate.id === event.id)) events.push(event);
    }
  }
  return { store, events };
}

function demoBlockHash(blockNumber) {
  return b64url(utf8(`byoid-static-block:${blockNumber}`)).slice(0, 43);
}

async function withResolutionMetadata(did, resolution, store) {
  const name = anchorName(did, 'byoid');
  const block = store.blockHeight
    ? { blockNumber: store.blockHeight, blockHash: demoBlockHash(store.blockHeight) }
    : null;
  resolution.anchorName = name;
  resolution.block = block;
  resolution.source = {
    node: 'GitHub Pages demo',
    name,
    block,
    static: true,
  };
  return resolution;
}

async function resolveDid(did, wallet) {
  const { store, events } = collectEvents(did, wallet);
  const resolution = await reduceEvents(did, events);
  return withResolutionMetadata(did, resolution, store);
}

async function agentFingerprint() {
  return `sha256:${await sha256B64url(canonicalize(DEMO_AGENT_PUBLIC_JWK))}`;
}

async function agentInfo() {
  return {
    issuer: AGENT_ISSUER,
    kid: AGENT_KID,
    publicJwk: DEMO_AGENT_PUBLIC_JWK,
    fingerprint: await agentFingerprint(),
    createdAt: '2026-11-08T00:00:00.000Z',
    role: 'static demo identity-link agent',
    chainAnchor: {
      status: 'demo',
      name: AGENT_NAME,
      blockNumber: 1,
      deployId: 'static-demo',
      confirmedAt: '2026-11-08T00:00:00.000Z',
      publicJwk: DEMO_AGENT_PUBLIC_JWK,
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
      version: '0.1.0-static',
      description: 'Bring Your Own Identity — a browser-only POC hosted on GitHub Pages.',
    },
    static: true,
    publicUrl: publicUrl(),
    chain: {
      url: 'GitHub Pages demo (browser-local)',
      shardId: '/demo',
      writes: true,
      simulated: true,
      anchorPrefix: 'byoid',
      agentName: AGENT_NAME,
      faucet: false,
      phloLimit: 0,
    },
    providers: publicProviders(),
    agent: await agentInfo(),
    limits: { anchorPerMinute: 0, maxEventBytes: 16 * 1024 },
    demoMode: true,
  };
}

function chainStatus() {
  const store = readStore();
  const height = store.blockHeight;
  return {
    ok: true,
    static: true,
    url: 'GitHub Pages demo (browser-local)',
    fetchedAt: new Date().toISOString(),
    status: {
      networkId: 'github-pages',
      shardId: '/demo',
      latestBlockNumber: height,
      proposeOnDeploy: false,
      version: { node: 'BYOID static demo' },
    },
    capabilities: {
      autopropose: false,
      proposeOnDeploy: false,
      manualPropose: true,
      adminHttp: false,
      devMode: true,
      faucet: false,
    },
    latestBlock: height
      ? { blockNumber: height, blockHash: demoBlockHash(height) }
      : null,
    errors: [],
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

function createJobs() {
  const jobs = new Map();
  let sequence = 0;
  return {
    create(payload) {
      const id = `static-job-${++sequence}-${randomB64url(6)}`;
      const job = { id, status: 'running', steps: [], ...payload };
      jobs.set(id, job);
      return job;
    },
    get(id) {
      return jobs.get(id) || null;
    },
  };
}

export function createStaticBackend({ getWallet = readWalletSnapshot } = {}) {
  const jobs = createJobs();
  const wallet = () => {
    try {
      return getWallet() || readWalletSnapshot();
    } catch {
      return readWalletSnapshot();
    }
  };

  async function anchorEvent(did, event) {
    if (!isDid(did)) throw httpError(400, 'invalid-did', 'a valid did:byoid identifier is required');
    if (!event || typeof event !== 'object') {
      throw httpError(400, 'missing-event', 'an event object is required');
    }
    validateEventShape(event);
    if (event.did !== did) throw httpError(400, 'invalid-event', 'event belongs to a different DID');

    const currentWallet = wallet();
    const { store, events } = collectEvents(did, currentWallet);
    const resolution = await reduceEvents(did, events);

    if (events.some((candidate) => candidate.id === event.id)) {
      return { alreadyAnchored: true, resolution: await withResolutionMetadata(did, resolution, store) };
    }

    const isCreate = event.type === EVENT_TYPES.CREATE;
    if (isCreate) {
      if (resolution.status.valid) {
        throw httpError(409, 'create-exists', 'this DID already has a create event in the demo log');
      }
      if (!(await verifyEventSignature(event.payload.publicKeyJwk, event))) {
        throw httpError(400, 'invalid-event', 'create event signature does not verify');
      }
    } else {
      if (!resolution.status.valid) {
        throw httpError(
          409,
          'stale-sequence',
          'the DID has no valid create event in the demo log',
          { resolution: await withResolutionMetadata(did, resolution, store) },
        );
      }
      if (
        event.seq !== resolution.status.latestSeq + 1 ||
        event.prev !== resolution.status.latestEventId
      ) {
        throw httpError(
          409,
          'stale-sequence',
          'the event does not extend the current demo log tip',
          { resolution: await withResolutionMetadata(did, resolution, store) },
        );
      }
      if (!(await verifyEventSignature(resolution.publicKeyJwk, event))) {
        throw httpError(400, 'invalid-event', 'event signature does not verify');
      }
    }

    const expectedId = await eventId(event);
    if (expectedId !== event.id) {
      throw httpError(400, 'invalid-event', 'event id does not match its content');
    }

    const nextEvents = [...events, event].slice(-MAX_EVENTS_PER_DID);
    const nextResolution = await reduceEvents(did, nextEvents);
    if (!nextResolution.events.some((candidate) => candidate.id === event.id)) {
      throw httpError(400, 'invalid-event', 'the event did not join the canonical demo log');
    }

    const blockNumber = store.blockHeight + 1;
    const now = new Date().toISOString();
    store.blockHeight = blockNumber;
    store.dids[did] = nextEvents;
    writeStore(store);

    const receipt = {
      eventId: event.id,
      eventType: event.type,
      eventSeq: event.seq,
      deployId: randomB64url(32),
      submittedAt: now,
      confirmedAt: now,
      blockHash: demoBlockHash(blockNumber),
      blockNumber,
      postStateHash: randomB64url(32),
      static: true,
      simulated: true,
      term: `@"${anchorName(did, 'byoid')}"!(${JSON.stringify(b64url(utf8(JSON.stringify(event))))})`,
    };
    const finalResolution = await withResolutionMetadata(did, nextResolution, store);
    return { receipt, resolution: finalResolution, event };
  }

  function startJob(result) {
    const job = jobs.create({ status: 'running', steps: [] });
    job.steps = PROGRESS_STEPS.map((step) => ({
      ...step,
      status: 'done',
      detail:
        step.key === 'submitted'
          ? result.receipt.deployId.slice(0, 12)
          : step.key === 'included'
            ? `demo block ${result.receipt.blockNumber}`
            : '',
    }));
    job.status = 'done';
    job.receipt = result.receipt;
    job.resolution = result.resolution;
    job.event = result.event;
    return job;
  }

  async function ingestEvidence(presentation) {
    const evidence = presentation?.byoidEvidence;
    if (!evidence) return 0;
    const list = Array.isArray(evidence) ? evidence : [evidence];
    const store = readStore();
    let added = 0;
    for (const entry of list) {
      if (!entry || !isDid(entry.did) || !Array.isArray(entry.events)) continue;
      const existing = store.dids[entry.did] || [];
      for (const event of entry.events) {
        if (!event || event.did !== entry.did) continue;
        if (existing.some((candidate) => candidate.id === event.id)) continue;
        existing.push(event);
        added += 1;
      }
      store.dids[entry.did] = existing.slice(-MAX_EVENTS_PER_DID);
    }
    if (added) writeStore(store);
    return added;
  }

  function evidenceFor(did) {
    const { events } = collectEvents(did, wallet());
    return events;
  }

  async function request(path, { method = 'GET', body } = {}) {
    const url = new URL(path, window.location.origin);
    const pathname = url.pathname;
    const verb = String(method || 'GET').toUpperCase();

    if (verb === 'GET' && pathname === '/api/config') return config();
    if (verb === 'GET' && pathname === '/api/chain/status') return chainStatus();
    if (verb === 'GET' && pathname === '/api/agent') {
      return { ...(await agentInfo()), chainWrites: true, agentName: AGENT_NAME };
    }
    if (verb === 'POST' && pathname === '/api/agent/anchor') {
      const info = await agentInfo();
      return { anchor: info.chainAnchor, agent: info };
    }

    if (verb === 'GET' && pathname.startsWith('/api/did/')) {
      const did = decodeURIComponent(pathname.slice('/api/did/'.length));
      return resolveDid(did, wallet());
    }

    if (verb === 'POST' && pathname === '/api/anchor') {
      const result = await anchorEvent(body?.did, body?.event);
      if (result.alreadyAnchored) {
        return { alreadyAnchored: true, resolution: result.resolution };
      }
      const job = startJob(result);
      return { jobId: job.id, status: 'queued', steps: job.steps, static: true };
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
        const result = await verifyPresentation({
          presentation: body.presentation,
          resolveDid: (did) => resolveDid(did, wallet()),
          agentPublicJwk: DEMO_AGENT_PUBLIC_JWK,
          agentKid: AGENT_KID,
        });
        return result;
      }
      if (body?.credential) {
        const issuer = body.credential.issuer;
        if (!isDid(issuer)) {
          throw httpError(400, 'invalid-did', 'a valid did:byoid identifier is required');
        }
        const resolution = await resolveDid(issuer, wallet());
        return verifyCredential({
          credential: body.credential,
          resolution,
          agentPublicJwk: DEMO_AGENT_PUBLIC_JWK,
          agentKid: AGENT_KID,
        });
      }
      throw httpError(400, 'missing-document', 'send { presentation } or { credential }');
    }

    if (verb === 'GET' && pathname.startsWith('/api/chain/deploy/')) {
      return {
        static: true,
        deployId: decodeURIComponent(pathname.slice('/api/chain/deploy/'.length)),
        note: 'Static GitHub Pages demo: deploy status is simulated locally.',
      };
    }
    if (verb === 'GET' && pathname.startsWith('/api/chain/block/')) {
      return {
        static: true,
        blockHash: decodeURIComponent(pathname.slice('/api/chain/block/'.length)),
        note: 'Static GitHub Pages demo: block data is simulated locally.',
      };
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
  }

  return {
    request,
    ingestEvidence,
    evidenceFor,
    publicJwk: DEMO_AGENT_PUBLIC_JWK,
    kid: AGENT_KID,
    issuer: AGENT_ISSUER,
  };
}
