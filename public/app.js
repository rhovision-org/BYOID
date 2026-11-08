// BYOID POC — browser wallet, provider linking, credential issuance, and
// verifier. All signing and verification uses the shared module; the server
// never sees the wallet's private key.

import {
  anchorName,
  b64url,
  buildDIDDocument,
  canonicalize,
  didFromPublicJwk,
  eventBody,
  eventTypeLabel,
  EVENT_TYPES,
  finalizeEvent,
  isDid,
  isRevAddress,
  publicJwkOf,
  sha256B64url,
  shortId,
  signEs256,
  unb64url,
  utf8,
  verifyCredential,
  verifyJws,
  verifyPresentation,
} from './shared.js';
import { createStaticBackend, STATIC_MODE } from './static-mode.js';
import {
  BUILT_IN_NODES,
  DEFAULT_NODE,
  allNodes,
  findNode,
  loadCustomNodes,
  loadSelectedNode,
  newCustomNode,
  nodeUrl,
  saveCustomNodes,
  saveSelectedNode,
  validateNodeDraft,
} from './nodes.js';
import {
  accountUrl,
  generateRevKey,
  proofCardBody,
  revKeyFromPrivateKey,
  signRevProof,
  verifyProofCard,
} from './rev-proof.js';

const WALLET_KEY = 'byoid.wallet.v1';
const TAB_KEY = 'byoid.tab.v1';
const DB_NAME = 'byoid-poc';
const DB_STORE = 'keys';
const PRIVATE_KEY_ID = 'wallet-key';
const REV_PROOF_KEY_ID = 'rev-proof-key';
const DEFAULT_ISSUE_FIELDS = {
  handle: true,
  email: false,
  emailVerified: true,
  verifiedAt: true,
  name: false,
};

const state = {
  config: null,
  chain: null,
  agent: null,
  wallet: null,
  privateKey: null,
  keyError: null,
  resolution: null,
  resolutionAt: 0,
  tab: localStorage.getItem(TAB_KEY) || 'wallet',
  busy: null,
  progress: null,
  modal: null,
  selectedCredentials: new Set(),
  verifier: { status: 'idle', presentation: null, result: null, error: null },
  revKey: null,
  proofQuery: '',
  proofLookup: { status: 'idle', query: '', result: null, error: null },
  didCache: new Map(),
  toastSeq: 0,
  progressSeq: 0,
  node: loadSelectedNode(),
  customNodes: loadCustomNodes(),
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

// GitHub Pages has no Node process. In static mode, API calls are served by a
// browser-local backend that writes directly to the live rholo playground.
const staticBackend = STATIC_MODE
  ? createStaticBackend({ getWallet: () => state.wallet, nodeUrl: nodeUrl(state.node) })
  : null;

// ── formatting / small helpers ──────────────────────────────────────────────

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => {
    switch (ch) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      default: return '&#39;';
    }
  });
}

function fmtDate(value, { short = false } = {}) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: short ? undefined : 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function fmtRelative(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const units = [
    ['year', 31536000],
    ['month', 2592000],
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1],
  ];
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size || unit === 'second') {
      return formatter.format(Math.round(seconds / size), unit);
    }
  }
  return '';
}

async function copyText(text, successMessage = 'Copied to clipboard') {
  try {
    await navigator.clipboard.writeText(text);
    toast({ kind: 'ok', title: successMessage });
  } catch {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand('copy');
      toast({ kind: 'ok', title: successMessage });
    } catch {
      toast({ kind: 'bad', title: 'Could not copy', message: 'Select the text and copy it manually.' });
    }
    area.remove();
  }
}

function downloadJson(filename, value) {
  const blob = new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function toast({ kind = 'ok', title = '', message = '', timeout = 6500 }) {
  const host = $('#toasts');
  if (!host) return;
  const id = `toast-${++state.toastSeq}`;
  const icon = kind === 'ok' ? '✓' : kind === 'bad' ? '!' : kind === 'warn' ? '△' : 'i';
  const element = document.createElement('div');
  element.className = `toast ${kind}`;
  element.dataset.toastId = id;
  element.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <div class="toast-body">
      ${title ? `<strong>${esc(title)}</strong>` : ''}
      ${message ? `<span>${esc(message)}</span>` : ''}
    </div>
    <button class="toast-close" data-action="dismiss-toast" data-toast-id="${id}" aria-label="Dismiss">×</button>
  `;
  host.appendChild(element);
  if (timeout) {
    setTimeout(() => {
      element.style.opacity = '0';
      element.style.transform = 'translateY(6px)';
      setTimeout(() => element.remove(), 220);
    }, timeout);
  }
}

function setBusy(label) {
  state.busy = label;
  let indicator = $('#busy-indicator');
  if (!indicator) {
    indicator = document.createElement('div');
    indicator.id = 'busy-indicator';
    indicator.className = 'busy-indicator';
    document.body.appendChild(indicator);
  }
  indicator.hidden = false;
  indicator.innerHTML = `<span class="spinner"></span><span>${esc(label)}</span>`;
}

function clearBusy() {
  state.busy = null;
  const indicator = $('#busy-indicator');
  if (indicator) indicator.hidden = true;
}

async function withBusy(label, fn) {
  setBusy(label);
  try {
    return await fn();
  } finally {
    clearBusy();
  }
}

function scrollToId(id) {
  const element = document.getElementById(id);
  if (element) element.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── API ─────────────────────────────────────────────────────────────────────

async function api(path, { method = 'GET', body } = {}) {
  if (staticBackend) return staticBackend.request(path, { method, body });
  const response = await fetch(path, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  if (!response.ok) {
    const error = new Error(data?.error?.message || `Request failed with HTTP ${response.status}`);
    error.code = data?.error?.code || 'http-error';
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

// ── IndexedDB key store ─────────────────────────────────────────────────────

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(DB_STORE)) db.createObjectStore(DB_STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function idbGet(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readonly');
    const request = tx.objectStore(DB_STORE).get(key);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

async function idbPut(key, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readwrite');
    tx.objectStore(DB_STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbDelete(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readwrite');
    tx.objectStore(DB_STORE).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── wallet persistence ──────────────────────────────────────────────────────

function emptyWallet(did, publicJwk, createdAt) {
  return {
    version: 1,
    did,
    publicJwk,
    createdAt,
    fingerprint: null,
    createEvent: null,
    createReceipt: null,
    createError: null,
    links: [],
    credentials: [],
    receipts: [],
    updatedAt: createdAt,
  };
}

function loadWalletMeta() {
  try {
    const raw = localStorage.getItem(WALLET_KEY);
    if (!raw) return null;
    const wallet = JSON.parse(raw);
    if (!wallet || wallet.version !== 1 || !isDid(wallet.did)) return null;
    return wallet;
  } catch {
    return null;
  }
}

function saveWallet() {
  if (!state.wallet) return;
  state.wallet.updatedAt = new Date().toISOString();
  localStorage.setItem(WALLET_KEY, JSON.stringify(state.wallet));
}

function ensureWalletShape(wallet) {
  if (!wallet) return wallet;
  wallet.links ||= [];
  wallet.credentials ||= [];
  wallet.receipts ||= [];
  return wallet;
}

async function ensureRevProofKey() {
  if (state.revKey) return state.revKey;
  let key = await idbGet(REV_PROOF_KEY_ID);
  try {
    key = key?.privateKeyHex ? revKeyFromPrivateKey(key.privateKeyHex) : null;
  } catch {
    key = null;
  }
  if (!key) {
    key = generateRevKey();
    await idbPut(REV_PROOF_KEY_ID, key);
  }
  state.revKey = key;
  return key;
}

// ── signing ─────────────────────────────────────────────────────────────────

function requireKey() {
  if (!state.privateKey) {
    throw new Error('Your signing key is not available in this browser. Import your wallet backup.');
  }
}

async function signEventWith({ did, privateKey, type, payload, seq, prev, at }) {
  const body = {
    v: 1,
    type,
    did,
    seq,
    prev,
    at: at || new Date().toISOString(),
    payload,
  };
  const signature = await signEs256(privateKey, utf8(canonicalize(body)));
  return finalizeEvent(body, signature);
}

function tipFromResolution(resolution) {
  if (resolution?.status?.valid) {
    return { seq: resolution.status.latestSeq, id: resolution.status.latestEventId };
  }
  return null;
}

async function currentTip() {
  const tip = tipFromResolution(state.resolution);
  if (tip) return tip;
  await refreshResolution({ force: true, quiet: true });
  return tipFromResolution(state.resolution);
}

async function signNextEvent(type, payload) {
  requireKey();
  const tip = await currentTip();
  if (!tip) throw new Error('Your DID has no anchored create event yet. Anchor your DID first.');
  return signEventWith({
    did: state.wallet.did,
    privateKey: state.privateKey,
    type,
    payload,
    seq: tip.seq + 1,
    prev: tip.id,
  });
}

async function resignAtTip(event, resolution) {
  requireKey();
  const tip = tipFromResolution(resolution);
  if (!tip) throw new Error('Cannot retry: the server did not return a valid chain tip.');
  const body = eventBody(event);
  body.seq = tip.seq + 1;
  body.prev = tip.id;
  body.at = new Date().toISOString();
  const signature = await signEs256(state.privateKey, utf8(canonicalize(body)));
  return finalizeEvent(body, signature);
}

// ── chain resolution ────────────────────────────────────────────────────────

async function fetchResolution(did, { force = false } = {}) {
  const cached = state.didCache.get(did);
  if (!force && cached && Date.now() - cached._at < 5000) return cached;
  const resolution = await api(`/api/did/${encodeURIComponent(did)}${force ? '?force=1' : ''}`);
  resolution._at = Date.now();
  state.didCache.set(did, resolution);
  return resolution;
}

async function refreshResolution({ force = true, quiet = false } = {}) {
  if (!state.wallet?.did) {
    state.resolution = null;
    return null;
  }
  try {
    const resolution = await fetchResolution(state.wallet.did, { force });
    state.resolution = resolution;
    state.resolutionAt = Date.now();
    mergeResolutionIntoWallet(resolution);
    saveWallet();
    if (!quiet) renderAll();
    return resolution;
  } catch (error) {
    state.resolution = {
      did: state.wallet.did,
      status: {
        valid: false,
        forked: false,
        gaps: false,
        deactivated: false,
        eventCount: 0,
        latestSeq: 0,
        latestEventId: null,
        rejectedCount: 0,
        errors: [error.message],
      },
      didDocument: null,
      events: [],
      links: [],
      revocations: [],
      publicKeyJwk: null,
      block: null,
    };
    if (!quiet) {
      toast({
        kind: 'bad',
        title: 'Could not read the DID from rholo',
        message: error.message,
      });
    }
    return null;
  }
}

function mergeResolutionIntoWallet(resolution) {
  if (!state.wallet) return;
  const chainEventIds = new Set((resolution.events || []).map((event) => event.id));
  if (state.wallet.createEvent) {
    state.wallet.createAnchored = chainEventIds.has(state.wallet.createEvent.id);
  }
  for (const link of state.wallet.links || []) {
    link.anchored = Boolean(link.event && chainEventIds.has(link.event.id));
    link.chainLink = (resolution.links || []).find(
      (candidate) => candidate.attestationHash === link.attestationHash,
    ) || null;
  }
  for (const credential of state.wallet.credentials || []) {
    credential.revokedOnChain = (resolution.revocations || []).some(
      (revocation) => revocation.credentialId === credential.id,
    );
  }
  const resolvedBlock = Number(resolution.block?.blockNumber);
  if (Number.isFinite(resolvedBlock) && state.chain?.status) {
    state.chain.status.latestBlockNumber = Math.max(
      Number(state.chain.status.latestBlockNumber) || 0,
      resolvedBlock,
    );
    if (state.chain.latestBlock) state.chain.latestBlock.blockNumber = resolvedBlock;
  }
}

// A receipt can belong to another rnode. Trust the currently resolved chain
// first, and fall back to the local receipt only when resolution is unavailable.
function walletCreateAnchored() {
  const wallet = state.wallet;
  if (!wallet) return false;
  if (state.resolution) {
    return Boolean(
      state.resolution.status?.valid &&
        state.resolution.events?.some((event) => event.id === wallet.createEvent?.id),
    );
  }
  return Boolean(wallet.createReceipt);
}

function activeNodeLabel() {
  if (STATIC_MODE && state.node?.name) return state.node.name;
  return state.chain?.status?.networkId || 'rholo playground';
}

function currentChainKey() {
  return STATIC_MODE
    ? nodeUrl(state.node)
    : state.config?.chain?.url || state.chain?.url || '';
}

function receiptMatchesChain(receipt) {
  return Boolean(receipt) && (!receipt.chain || receipt.chain === currentChainKey());
}

function linkIsAnchored(link) {
  if (!link?.event) return false;
  if (state.resolution) {
    return Boolean(state.resolution.events?.some((event) => event.id === link.event.id));
  }
  return Boolean(link.receipt || link.anchored);
}

// ── anchor jobs / progress ──────────────────────────────────────────────────

const PROGRESS_STEPS = [
  { key: 'validated', label: 'Signature and sequence checked' },
  { key: 'submitted', label: 'Deploy accepted by rholo' },
  { key: 'executed', label: 'Executed without error' },
  { key: 'included', label: 'Included in a block' },
  { key: 'observed', label: 'Observed at the DID anchor name' },
];

function renderProgress() {
  const root = $('#progress-root');
  if (!root) return;
  if (!state.progress) {
    root.innerHTML = '';
    return;
  }
  const progress = state.progress;
  const steps = progress.steps || PROGRESS_STEPS.map((step) => ({ ...step, status: 'pending', detail: '' }));
  const done = steps.filter((step) => step.status === 'done').length;
  const statusText =
    progress.status === 'done'
      ? 'confirmed'
      : progress.status === 'error'
        ? 'failed'
        : `${done}/${steps.length} confirmed`;
  root.innerHTML = `
    <div class="progress-card" role="status">
      <div class="progress-head">
        <div>
          <h3>${esc(progress.title || 'Anchoring on rholo')}</h3>
          <span>${esc(statusText)}</span>
        </div>
        <button class="modal-close" data-action="close-progress" aria-label="Close progress">×</button>
      </div>
      <div class="progress-steps">
        ${steps
          .map(
            (step) => `
          <div class="progress-step is-${esc(step.status)}">
            <span class="marker">${step.status === 'done' ? '✓' : step.status === 'failed' ? '!' : ''}</span>
            <span>${esc(step.label)}</span>
            ${step.detail ? `<span class="detail">${esc(step.detail)}</span>` : ''}
          </div>`,
          )
          .join('')}
      </div>
      ${
        progress.receipt
          ? `<div class="progress-foot"><span class="mono">${esc(shortId(progress.receipt.deployId || '', 12, 8))}</span><span>block ${esc(progress.receipt.blockNumber)}</span></div>`
          : progress.jobId
            ? `<div class="progress-foot"><span class="mono">job ${esc(shortId(progress.jobId, 10, 6))}</span><span>${esc(activeNodeLabel())}</span></div>`
            : ''
      }
      ${progress.error ? `<div class="progress-error">${esc(progress.error)}</div>` : ''}
    </div>
  `;
}

async function pollAnchorJob(jobId) {
  const started = Date.now();
  for (;;) {
    if (Date.now() - started > 120000) throw new Error('The anchor job did not finish within two minutes.');
    const job = await api(`/api/anchor/jobs/${encodeURIComponent(jobId)}`);
    if (state.progress?.jobId === jobId) {
      state.progress.steps = job.steps;
      state.progress.status = job.status;
      state.progress.receipt = job.receipt;
      state.progress.error = job.error?.message || null;
      renderProgress();
    }
    if (job.status === 'done') return job;
    if (job.status === 'error') {
      const error = new Error(job.error?.message || 'Anchor failed');
      error.code = job.error?.code || 'anchor-failed';
      error.data = { resolution: job.error?.resolution || job.resolution || null };
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

async function anchorWithRetry(event, title, { retries = 1 } = {}) {
  const progressId = ++state.progressSeq;
  state.progress = {
    id: progressId,
    title,
    jobId: null,
    status: 'running',
    steps: PROGRESS_STEPS.map((step) => ({ ...step, status: 'pending', detail: '' })),
    receipt: null,
    error: null,
  };
  renderProgress();

  try {
    let candidate = event;
    let attempts = retries;
    for (;;) {
      let response;
      try {
        response = await api('/api/anchor', { method: 'POST', body: { did: state.wallet.did, event: candidate } });
      } catch (error) {
        if (error.code === 'stale-sequence' && error.data?.resolution && attempts > 0) {
          attempts -= 1;
          state.resolution = error.data.resolution;
          mergeResolutionIntoWallet(state.resolution);
          candidate = await resignAtTip(candidate, error.data.resolution);
          state.progress.steps[0].status = 'active';
          renderProgress();
          continue;
        }
        throw error;
      }
      if (response?.alreadyAnchored) {
        state.progress.status = 'done';
        state.progress.steps = state.progress.steps.map((step) => ({ ...step, status: 'done' }));
        renderProgress();
        setTimeout(() => {
          if (state.progress?.id === progressId) {
            state.progress = null;
            renderProgress();
          }
        }, 2200);
        return { alreadyAnchored: true, resolution: response.resolution, event: candidate };
      }
      state.progress.jobId = response.jobId;
      renderProgress();
      try {
        const job = await pollAnchorJob(response.jobId);
        state.progress.status = 'done';
        state.progress.receipt = job.receipt;
        renderProgress();
        setTimeout(() => {
          if (state.progress?.id === progressId) {
            state.progress = null;
            renderProgress();
          }
        }, 2600);
        const receipt = job.receipt ? { ...job.receipt, chain: currentChainKey() } : null;
        return { receipt, resolution: job.resolution, event: candidate };
      } catch (error) {
        if (error.code === 'stale-sequence' && error.data?.resolution && attempts > 0) {
          attempts -= 1;
          state.resolution = error.data.resolution;
          mergeResolutionIntoWallet(state.resolution);
          candidate = await resignAtTip(candidate, error.data.resolution);
          state.progress.jobId = null;
          state.progress.status = 'running';
          state.progress.error = null;
          state.progress.steps = PROGRESS_STEPS.map((step) => ({ ...step, status: 'pending', detail: '' }));
          renderProgress();
          continue;
        }
        throw error;
      }
    }
  } catch (error) {
    state.progress.status = 'error';
    state.progress.error = error.message;
    renderProgress();
    throw error;
  }
}

function recordReceipt(receipt) {
  if (!receipt || !state.wallet) return;
  state.wallet.receipts = (state.wallet.receipts || []).filter(
    (item) => item.eventId !== receipt.eventId,
  );
  state.wallet.receipts.unshift({
    eventId: receipt.eventId,
    eventType: receipt.eventType,
    eventSeq: receipt.eventSeq,
    deployId: receipt.deployId,
    submittedAt: receipt.submittedAt,
    confirmedAt: receipt.confirmedAt,
    chain: receipt.chain || currentChainKey(),
    blockHash: receipt.blockHash,
    blockNumber: receipt.blockNumber,
    stateHash: receipt.postStateHash || receipt.preStateHash || null,
    term: receipt.term,
  });
  state.wallet.receipts = state.wallet.receipts.slice(0, 60);
  saveWallet();
}

function findReceipt(eventId) {
  if (!state.wallet || !eventId) return null;
  if (state.wallet.createReceipt?.eventId === eventId && receiptMatchesChain(state.wallet.createReceipt)) {
    return state.wallet.createReceipt;
  }
  for (const link of state.wallet.links || []) {
    if (link.receipt?.eventId === eventId && receiptMatchesChain(link.receipt)) return link.receipt;
  }
  for (const credential of state.wallet.credentials || []) {
    if (
      credential.revokeReceipt?.eventId === eventId &&
      receiptMatchesChain(credential.revokeReceipt)
    ) {
      return credential.revokeReceipt;
    }
  }
  return (
    (state.wallet.receipts || []).find(
      (receipt) => receipt.eventId === eventId && receiptMatchesChain(receipt),
    ) || null
  );
}

// ── identity creation / import / export ─────────────────────────────────────

async function createIdentity() {
  if (state.wallet) {
    toast({ kind: 'warn', title: 'You already have an identity', message: 'Export it first if you want to start over.' });
    return;
  }
  await withBusy('Generating a P-256 key in your browser…', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    const publicJwk = publicJwkOf(await crypto.subtle.exportKey('jwk', pair.publicKey));
    const did = await didFromPublicJwk(publicJwk);
    const createdAt = new Date().toISOString();
    const fingerprint = `sha256:${await sha256B64url(canonicalize(publicJwk))}`;
    const didDocument = buildDIDDocument({
      did,
      publicJwk,
      serviceEndpoint: state.config?.publicUrl || location.origin,
      createdAt,
    });
    const network = state.chain?.status || {};
    const createEvent = await signEventWith({
      did,
      privateKey: pair.privateKey,
      type: EVENT_TYPES.CREATE,
      seq: 1,
      prev: null,
      at: createdAt,
      payload: {
        publicKeyJwk: publicJwk,
        didDocument,
        method: {
          chain: 'rholo',
          network: network.networkId || null,
          shardId: network.shardId || state.config?.chain?.shardId || null,
          name: anchorName(did, state.config?.chain?.anchorPrefix || 'byoid'),
          serviceEndpoint: state.config?.publicUrl || location.origin,
        },
      },
    });

    const wallet = emptyWallet(did, publicJwk, createdAt);
    wallet.fingerprint = fingerprint;
    wallet.createEvent = createEvent;
    state.wallet = wallet;
    state.privateKey = pair.privateKey;
    await idbPut(PRIVATE_KEY_ID, pair.privateKey);
    await ensureRevProofKey().catch(() => {});
    saveWallet();
    renderAll();
    scrollToId('wallet-root');
    toast({
      kind: 'ok',
      title: 'Identity created',
      message: 'The private key never leaves this browser. Now anchor the DID on rholo.',
    });

    try {
      const result = await anchorWithRetry(createEvent, 'Anchoring your DID');
      if (result.receipt) {
        wallet.createReceipt = result.receipt;
        recordReceipt(result.receipt);
      }
      if (result.resolution) {
        state.resolution = result.resolution;
        state.didCache.set(wallet.did, result.resolution);
        mergeResolutionIntoWallet(result.resolution);
      }
      wallet.createError = null;
      saveWallet();
      await refreshResolution({ force: true, quiet: true });
      renderAll();
      toast({
        kind: 'ok',
        title: 'DID anchored on rholo',
        message: result.receipt
          ? `Confirmed in block ${result.receipt.blockNumber}.`
          : 'The create event is already on chain.',
      });
    } catch (error) {
      wallet.createError = error.message;
      saveWallet();
      renderAll();
      toast({
        kind: 'bad',
        title: 'Identity is saved locally, but the anchor failed',
        message: `${error.message} Use “Anchor now” to retry.`,
      });
    }
  });
}

async function retryCreateAnchor() {
  if (!state.wallet?.createEvent) return;
  if (state.keyError || !state.privateKey) {
    toast({ kind: 'bad', title: 'Signing key unavailable', message: 'Import your wallet backup first.' });
    return;
  }
  try {
    const result = await anchorWithRetry(state.wallet.createEvent, 'Anchoring your DID');
    if (result.receipt) state.wallet.createReceipt = result.receipt;
    if (result.receipt) recordReceipt(result.receipt);
    if (result.resolution) {
      state.resolution = result.resolution;
      mergeResolutionIntoWallet(result.resolution);
    }
    state.wallet.createError = null;
    saveWallet();
    await refreshResolution({ force: true, quiet: true });
    renderAll();
    toast({ kind: 'ok', title: 'DID anchored', message: 'You can connect accounts now.' });
  } catch (error) {
    state.wallet.createError = error.message;
    saveWallet();
    renderAll();
    toast({ kind: 'bad', title: 'Anchor failed', message: error.message });
  }
}

async function exportWallet() {
  if (!state.wallet || !state.privateKey) {
    toast({ kind: 'bad', title: 'Nothing to export', message: 'Create or import a wallet first.' });
    return;
  }
  const privateJwk = await crypto.subtle.exportKey('jwk', state.privateKey);
  downloadJson(`byoid-wallet-${shortId(state.wallet.did, 14, 8)}.json`, {
    ...state.wallet,
    privateJwk,
    exportedAt: new Date().toISOString(),
    warning: 'This file contains your private key. Anyone who has it can act as this DID.',
  });
  toast({
    kind: 'warn',
    title: 'Wallet exported',
    message: 'The file contains the private key. Store it somewhere safe.',
  });
}

async function importWalletFile(file) {
  let parsed;
  try {
    parsed = JSON.parse(await file.text());
  } catch {
    toast({ kind: 'bad', title: 'Not a wallet file', message: 'The selected file is not valid JSON.' });
    return;
  }
  try {
    if (!parsed?.privateJwk || !isDid(parsed.did) || !parsed.publicJwk) {
      throw new Error('The file is missing did, publicJwk or privateJwk.');
    }
    const derived = await didFromPublicJwk(parsed.publicJwk);
    if (derived !== parsed.did) throw new Error('The public key does not derive the wallet DID.');
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      {
        kty: parsed.privateJwk.kty,
        crv: parsed.privateJwk.crv,
        x: parsed.privateJwk.x,
        y: parsed.privateJwk.y,
        d: parsed.privateJwk.d,
      },
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign'],
    );
    const challenge = utf8('byoid-wallet-import-check');
    const signature = await signEs256(privateKey, challenge);
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      publicJwkOf(parsed.publicJwk),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signature,
      challenge,
    );
    if (!valid) throw new Error('The private key does not match the public key.');
    const wallet = ensureWalletShape({ ...parsed });
    delete wallet.privateJwk;
    delete wallet.exportedAt;
    delete wallet.warning;
    wallet.version = 1;
    state.wallet = wallet;
    state.privateKey = privateKey;
    state.keyError = null;
    state.selectedCredentials = new Set();
    await idbPut(PRIVATE_KEY_ID, privateKey);
    await ensureRevProofKey().catch(() => {});
    saveWallet();
    state.modal = null;
    renderAll();
    await refreshResolution({ force: true, quiet: true });
    toast({ kind: 'ok', title: 'Wallet imported', message: parsed.did });
  } catch (error) {
    toast({ kind: 'bad', title: 'Could not import that wallet', message: error.message });
  }
}

async function clearWallet() {
  if (!window.confirm('Remove this wallet from this browser? Export it first if you want a backup.')) return;
  localStorage.removeItem(WALLET_KEY);
  await idbDelete(PRIVATE_KEY_ID).catch(() => {});
  await idbDelete(REV_PROOF_KEY_ID).catch(() => {});
  state.wallet = null;
  state.privateKey = null;
  state.keyError = null;
  state.revKey = null;
  state.proofQuery = '';
  state.proofLookup = { status: 'idle', query: '', result: null, error: null };
  state.resolution = null;
  state.selectedCredentials = new Set();
  state.verifier = { status: 'idle', presentation: null, result: null, error: null };
  state.didCache.clear();
  state.modal = null;
  renderAll();
  toast({ kind: 'ok', title: 'Wallet cleared from this browser' });
}

async function startOverWithNewIdentity() {
  if (state.wallet) {
    const ok = window.confirm(
      'Start over with a new identity? The current wallet key will be removed from this browser. Export it first if you want to keep it.',
    );
    if (!ok) return;
  }
  localStorage.removeItem(WALLET_KEY);
  await idbDelete(PRIVATE_KEY_ID).catch(() => {});
  await idbDelete(REV_PROOF_KEY_ID).catch(() => {});
  state.wallet = null;
  state.privateKey = null;
  state.keyError = null;
  state.revKey = null;
  state.proofQuery = '';
  state.proofLookup = { status: 'idle', query: '', result: null, error: null };
  state.resolution = null;
  state.selectedCredentials = new Set();
  state.verifier = { status: 'idle', presentation: null, result: null, error: null };
  state.didCache.clear();
  state.modal = null;
  renderAll();
  if (state.chain) {
    toast({
      kind: 'warn',
      title: 'Starting over',
      message: 'The previous wallet was removed locally. Creating and anchoring a new DID now…',
    });
  }
  await createIdentity();
}

// ── rnode choice ────────────────────────────────────────────────────────────

function selectedNodeFromModal() {
  const modal = state.modal;
  if (!modal || modal.type !== 'node') return null;
  return findNode(modal.nodeId, state.customNodes) || state.node || DEFAULT_NODE;
}

async function applyNode(node) {
  if (!node) return;
  if (!staticBackend) {
    toast({
      kind: 'warn',
      title: 'The server chooses the rnode',
      message: 'Set RHOLO_URL in .env and restart the Node server to use a different rnode.',
    });
    return;
  }
  if (state.busy) {
    toast({
      kind: 'warn',
      title: 'Wait for the current chain write',
      message: 'Switch rnodes after the current deploy finishes.',
    });
    return;
  }
  await withBusy(`Connecting to ${node.name}…`, async () => {
    try {
      await api('/api/chain/node', { method: 'POST', body: { url: nodeUrl(node) } });
      state.node = node;
      saveSelectedNode(node);
      if (state.config?.chain) state.config.chain.url = nodeUrl(node);
      state.didCache.clear();
      state.resolution = null;
      try {
        state.chain = await api('/api/chain/status');
      } catch {
        state.chain = null;
      }
      if (state.config?.chain && state.chain?.status?.shardId) {
        state.config.chain.shardId = state.chain.status.shardId;
      }
      if (state.wallet) await refreshResolution({ force: true, quiet: true });
      state.modal = null;
      renderAll();
      const status = state.chain?.status;
      toast({
        kind: status ? 'ok' : 'warn',
        title: `Using ${node.name}`,
        message: status
          ? `${status.networkId || 'network'} · shard ${status.shardId || '—'} · block ${status.latestBlockNumber ?? '—'}`
          : `${nodeUrl(node)} is selected, but status is unavailable.`,
      });
    } catch (error) {
      toast({ kind: 'bad', title: 'Could not switch rnode', message: error.message });
    }
  });
}

async function useSelectedNode() {
  await applyNode(selectedNodeFromModal());
}

async function saveNodeDraft() {
  const modal = state.modal;
  if (!modal || modal.type !== 'node' || !modal.draft) return;
  const result = validateNodeDraft({
    id: modal.draft.id,
    name: $('#rnode-name')?.value,
    url: $('#rnode-url')?.value,
    port: $('#rnode-port')?.value,
  });
  if (!result.ok) {
    toast({ kind: 'warn', title: 'Check the node details', message: result.error });
    return;
  }
  const customNodes = [...state.customNodes];
  const index = customNodes.findIndex((node) => node.id === result.node.id);
  if (index >= 0) customNodes.splice(index, 1, result.node);
  else customNodes.push(result.node);
  state.customNodes = customNodes;
  saveCustomNodes(customNodes);
  await applyNode(result.node);
}

async function removeSelectedCustomNode() {
  const node = selectedNodeFromModal();
  if (!node?.editable) return;
  if (!window.confirm(`Remove the custom rnode "${node.name}" from this browser?`)) return;
  const customNodes = state.customNodes.filter((candidate) => candidate.id !== node.id);
  state.customNodes = customNodes;
  saveCustomNodes(customNodes);
  if (state.node?.id === node.id) {
    await applyNode(DEFAULT_NODE);
  } else {
    state.modal.nodeId = state.node?.id || DEFAULT_NODE.id;
    renderModal();
  }
}

// ── REV proof cards ─────────────────────────────────────────────────────────

function anchoredProofLinks() {
  return (state.wallet?.links || []).filter((link) => linkIsAnchored(link));
}

async function buildCurrentProofCard() {
  const wallet = state.wallet;
  if (!wallet) throw new Error('Create an identity before publishing proofs.');
  requireKey();
  const key = await ensureRevProofKey();
  const links = anchoredProofLinks();
  if (!links.length) {
    throw new Error('Anchor at least one provider link before publishing a proof card.');
  }
  const proofs = links.map((link) => {
    const handle = link.profile?.handle || null;
    return {
      provider: link.provider,
      handle,
      subjectHash: link.subjectHash,
      attestation: link.attestation,
      attestationHash: link.attestationHash,
      linkEventId: link.event?.id || null,
      linkedAt: link.linkedAt,
      demo: Boolean(link.demo || link.profile?.demo),
    };
  });
  const body = proofCardBody({
    revAddress: key.address,
    revPublicKey: key.publicKeyHex,
    did: wallet.did,
    proofs,
    network: state.chain?.status?.networkId || null,
    shardId: state.chain?.status?.shardId || null,
    agentFingerprint: state.agent?.fingerprint || null,
  });
  const bytes = utf8(canonicalize(body));
  const didSignature = b64url(await signEs256(state.privateKey, bytes));
  const revSignature = signRevProof(key.privateKeyHex, bytes);
  return { ...body, didSignature, revSignature };
}

async function publishRevProofs() {
  if (!state.wallet) {
    toast({ kind: 'warn', title: 'Create your identity first', message: 'A REV proof card binds the address to a DID.' });
    return;
  }
  if (!walletCreateAnchored()) {
    toast({ kind: 'warn', title: 'Anchor your DID first', message: 'Proof cards point at the canonical DID log.' });
    return;
  }
  await withBusy('Signing and anchoring the REV proof card…', async () => {
    try {
      const key = await ensureRevProofKey();
      const card = await buildCurrentProofCard();
      const response = await api('/api/rev/publish', {
        method: 'POST',
        body: { address: key.address, card },
      });
      state.wallet.revProof = {
        address: key.address,
        card,
        receipt: response,
        publishedAt: new Date().toISOString(),
      };
      recordReceipt(response);
      saveWallet();
      state.proofQuery = key.address;
      try {
        await lookupRevProofs(key.address);
      } catch (error) {
        state.proofLookup = {
          status: 'error',
          query: key.address,
          error: `Card published, but the lookup failed: ${error.message}`,
          result: null,
        };
      }
      renderAll();
      toast({
        kind: 'ok',
        title: 'REV proof card published',
        message: response.blockNumber
          ? `Anchored in block ${response.blockNumber}.`
          : 'The card is now readable at its public name.',
      });
    } catch (error) {
      toast({ kind: 'bad', title: 'Could not publish the proof card', message: error.message });
      renderChain();
    }
  });
}

async function currentAgent() {
  if (state.agent?.publicJwk) return state.agent;
  state.agent = await api('/api/agent');
  return state.agent;
}

async function lookupRevProofs(address) {
  const agent = await currentAgent();
  const response = await api(`/api/rev/${encodeURIComponent(address)}`);
  const verified = [];
  const cards = Array.isArray(response.cards) ? response.cards.slice(0, 20) : [];
  for (const card of cards) {
    if (!isDid(card?.did)) {
      verified.push({ ok: false, card, errors: ['card DID is not a did:byoid identifier'], checks: [], proofs: [] });
      continue;
    }
    try {
      const resolution = await fetchResolution(card.did, { force: true });
      const result = await verifyProofCard({
        card,
        address,
        resolution,
        agent,
      });
      verified.push({ ...result, card, resolution });
    } catch (error) {
      verified.push({ ok: false, card, errors: [error.message], checks: [], proofs: [] });
    }
  }
  const valid =
    verified
      .filter((candidate) => candidate.ok)
      .sort((a, b) => Date.parse(b.card.issuedAt || 0) - Date.parse(a.card.issuedAt || 0))[0] ||
    null;
  state.proofLookup = {
    status: 'done',
    query: address,
    error: null,
    result: {
      kind: 'rev',
      address,
      name: response.name,
      block: response.block,
      cards,
      invalidValues: response.invalid || [],
      valid,
      verified,
    },
  };
  renderChain();
}

async function lookupDidProofs(did) {
  const resolution = await fetchResolution(did, { force: true });
  state.proofLookup = {
    status: 'done',
    query: did,
    error: null,
    result: { kind: 'did', did, resolution },
  };
  renderChain();
}

async function lookupProofsFromInput() {
  const value = String($('#proof-query')?.value || '').trim();
  state.proofQuery = value;
  if (!value) {
    toast({ kind: 'warn', title: 'Enter a REV address or DID' });
    return;
  }
  if (isRevAddress(value)) {
    state.proofLookup = { status: 'loading', query: value, error: null, result: null };
    renderChain();
    try {
      await lookupRevProofs(value);
    } catch (error) {
      state.proofLookup = { status: 'error', query: value, error: error.message, result: null };
      renderChain();
    }
    return;
  }
  if (isDid(value)) {
    state.proofLookup = { status: 'loading', query: value, error: null, result: null };
    renderChain();
    try {
      await lookupDidProofs(value);
    } catch (error) {
      state.proofLookup = { status: 'error', query: value, error: error.message, result: null };
      renderChain();
    }
    return;
  }
  toast({
    kind: 'warn',
    title: 'That is not a REV address or DID',
    message: 'Use a base58 REV address, or did:byoid:…',
  });
}

// ── provider linking ────────────────────────────────────────────────────────

function providerById(id) {
  return state.config?.providers?.find((provider) => provider.id === id) || null;
}

function connectProvider(providerId) {
  const provider = providerById(providerId);
  if (!provider) return;
  if (!state.wallet) {
    toast({ kind: 'warn', title: 'Create your identity first', message: 'A DID is the anchor every account link is signed against.' });
    scrollToId('wallet-root');
    return;
  }
  if (!walletCreateAnchored()) {
    toast({ kind: 'warn', title: 'Anchor your DID first', message: 'The link event is appended to your on-chain DID log.' });
    retryCreateAnchor();
    return;
  }
  if (state.keyError || !state.privateKey) {
    toast({ kind: 'bad', title: 'Signing key unavailable', message: 'Import your wallet backup to sign a link event.' });
    return;
  }
  if (provider.mode === 'unconfigured') {
    state.modal = { type: 'help', section: 'oauth' };
    renderModal();
    return;
  }
  if (provider.mode === 'demo') {
    state.modal = {
      type: 'demo',
      providerId,
      profileId: provider.demoProfiles?.[0]?.id || null,
    };
    renderModal();
    return;
  }
  window.location.href = `/auth/${encodeURIComponent(providerId)}/start?did=${encodeURIComponent(state.wallet.did)}`;
}

async function authorizeDemo() {
  const modal = state.modal;
  if (!modal || modal.type !== 'demo' || !state.wallet) return;
  const provider = providerById(modal.providerId);
  if (!provider) return;
  await withBusy(`Asking the demo ${provider.name} provider…`, async () => {
    try {
      const response = await api('/api/demo/link', {
        method: 'POST',
        body: { provider: provider.id, profileId: modal.profileId, did: state.wallet.did },
      });
      state.modal = null;
      renderModal();
      await completeLink(response.link);
    } catch (error) {
      toast({ kind: 'bad', title: `${provider.name} link failed`, message: error.message });
    }
  });
}

async function completeLink(link) {
  if (!state.wallet) throw new Error('Create an identity before linking an account.');
  if (link.did !== state.wallet.did) {
    throw new Error('This sign-in is bound to a different DID. Start again from this wallet.');
  }
  const provider = providerById(link.provider);
  if (!provider) throw new Error('Unknown identity provider.');

  const agent = state.agent?.publicJwk ? state.agent : await api('/api/agent');
  const attestation = await verifyJws(agent.publicJwk, link.attestation);
  if (!attestation.ok || attestation.payload.sub !== state.wallet.did) {
    throw new Error('The agent attestation did not verify for this DID.');
  }
  if (attestation.payload.provider !== link.provider) {
    throw new Error('The attestation is for a different provider.');
  }

  const existing = (state.wallet.links || []).find((item) => item.provider === link.provider);
  if (
    existing &&
    existing.subjectHash === link.subjectHash &&
    existing.attestationHash === link.attestationHash &&
    (existing.receipt || existing.anchored)
  ) {
    state.wallet.links = state.wallet.links.map((item) =>
      item.provider === link.provider ? { ...item, ...link, receipt: item.receipt, anchored: item.anchored } : item,
    );
    saveWallet();
    renderAll();
    toast({
      kind: 'ok',
      title: `${provider.name} is already linked`,
      message: existing.receipt ? `Anchored in block ${existing.receipt.blockNumber}.` : 'The link event is on chain.',
    });
    return;
  }

  const tip = await currentTip();
  if (!tip) {
    throw new Error('Your create event is not anchored yet. Anchor your DID, then connect the account.');
  }
  const event = await signEventWith({
    did: state.wallet.did,
    privateKey: state.privateKey,
    type: EVENT_TYPES.LINK,
    seq: tip.seq + 1,
    prev: tip.id,
    payload: {
      provider: link.provider,
      subjectHash: link.subjectHash,
      attestationHash: link.attestationHash,
      linkedAt: link.linkedAt,
    },
  });

  const record = {
    ...link,
    event,
    receipt: null,
    anchored: false,
    anchorError: null,
  };
  state.wallet.links = [
    ...(state.wallet.links || []).filter((item) => item.provider !== link.provider),
    record,
  ];
  saveWallet();
  renderAll();

  try {
    const result = await anchorWithRetry(event, `Linking ${provider.name} to your DID`);
    record.receipt = result.receipt || null;
    record.anchored = Boolean(
      result.alreadyAnchored ||
        result.resolution?.events?.some((candidate) => candidate.id === event.id),
    );
    record.anchorError = null;
    if (result.receipt) recordReceipt(result.receipt);
    if (result.resolution) {
      state.resolution = result.resolution;
      state.didCache.set(state.wallet.did, result.resolution);
      mergeResolutionIntoWallet(result.resolution);
    }
    saveWallet();
    await refreshResolution({ force: true, quiet: true });
    renderAll();
    toast({
      kind: 'ok',
      title: `${provider.name} linked`,
      message: record.receipt
        ? `The signed link event is anchored in block ${record.receipt.blockNumber}.`
        : 'The signed link event is on chain.',
    });
  } catch (error) {
    record.anchorError = error.message;
    saveWallet();
    renderAll();
    toast({
      kind: 'bad',
      title: `${provider.name} is saved locally, but the link anchor failed`,
      message: `${error.message} You can retry the anchor from the provider card.`,
    });
  }
}

async function retryLinkAnchor(providerId) {
  const link = (state.wallet?.links || []).find((item) => item.provider === providerId);
  if (!link?.event) return;
  const provider = providerById(providerId);
  try {
    const result = await anchorWithRetry(link.event, `Linking ${provider?.name || providerId} to your DID`);
    link.receipt = result.receipt || null;
    link.anchored = Boolean(
      result.alreadyAnchored ||
        result.resolution?.events?.some((candidate) => candidate.id === link.event.id),
    );
    link.anchorError = null;
    if (result.receipt) recordReceipt(result.receipt);
    if (result.resolution) {
      state.resolution = result.resolution;
      mergeResolutionIntoWallet(result.resolution);
    }
    saveWallet();
    await refreshResolution({ force: true, quiet: true });
    renderAll();
    toast({ kind: 'ok', title: 'Link anchored', message: 'The account is now in your on-chain DID log.' });
  } catch (error) {
    link.anchorError = error.message;
    saveWallet();
    renderAll();
    toast({ kind: 'bad', title: 'Link anchor failed', message: error.message });
  }
}

async function consumePendingLink() {
  try {
    const session = await api('/api/session');
    if (!session.pendingLink) {
      toast({ kind: 'warn', title: 'No pending sign-in found', message: 'Start a provider connection from your wallet.' });
      return;
    }
    if (!state.wallet) {
      await api('/api/session/consume-link', { method: 'POST' });
      toast({
        kind: 'bad',
        title: 'The sign-in belongs to an identity that is not in this browser',
        message: 'Create or import that wallet, then connect the provider again.',
      });
      return;
    }
    if (session.pendingLink.did !== state.wallet.did) {
      await api('/api/session/consume-link', { method: 'POST' });
      toast({
        kind: 'bad',
        title: 'This sign-in is bound to a different DID',
        message: 'Start the provider connection from the wallet you want to use.',
      });
      return;
    }
    const pending = session.pendingLink;
    await api('/api/session/consume-link', { method: 'POST' });
    await withBusy(`Completing the ${providerById(pending.provider)?.name || pending.provider} link…`, async () => {
      try {
        await completeLink(pending);
      } catch (error) {
        toast({ kind: 'bad', title: 'Could not complete the link', message: error.message });
      }
    });
  } catch (error) {
    toast({ kind: 'bad', title: 'Could not read the OAuth session', message: error.message });
  }
}

// ── credentials ─────────────────────────────────────────────────────────────

function fieldLabel(field) {
  return (
    {
      provider: 'Provider',
      handle: 'Handle',
      email: 'Email',
      emailVerified: 'Email verified',
      verifiedAt: 'Verified at',
      name: 'Name',
      subjectHash: 'Subject hash',
      attestationHash: 'Attestation hash',
    }[field] || field
  );
}

function credentialAccount(credential) {
  const subject = credential?.credentialSubject || {};
  return Array.isArray(subject.accounts) ? subject.accounts[0] : subject.account;
}

function credentialSummary(credential) {
  const account = credentialAccount(credential.credential) || {};
  const fields = [];
  if (account.handle !== undefined) fields.push(['handle', account.handle]);
  if (account.email !== undefined) fields.push(['email', account.email]);
  if (account.name !== undefined) fields.push(['name', account.name]);
  if (account.emailVerified !== undefined) fields.push(['emailVerified', account.emailVerified ? 'yes' : 'not asserted']);
  if (account.verifiedAt !== undefined) fields.push(['verifiedAt', fmtDate(account.verifiedAt)]);
  const hidden = [];
  if (account.handle === undefined) hidden.push('handle');
  if (account.email === undefined) hidden.push('email');
  if (account.name === undefined) hidden.push('name');
  return {
    account,
    providerId: account.provider || credential.provider,
    fields,
    hidden,
    id: credential.credential?.id || credential.id,
    revoked: Boolean(credential.revokedAt || credential.revokedOnChain),
    issuedAt: credential.issuedAt || credential.credential?.issuanceDate,
  };
}

async function issueCredentialFromModal() {
  const modal = state.modal;
  if (!modal || modal.type !== 'issue') return;
  const link = (state.wallet?.links || []).find((item) => item.provider === modal.providerId);
  if (!link) {
    toast({ kind: 'bad', title: 'That account is not linked' });
    return;
  }
  if (!linkIsAnchored(link)) {
    toast({ kind: 'warn', title: 'Anchor the link first', message: 'The verifier checks the link event on rholo.' });
    return;
  }
  requireKey();
  const fields = modal.fields;
  const account = {
    provider: link.provider,
    subjectHash: link.subjectHash,
    attestationHash: link.attestationHash,
    attestation: link.attestation,
  };
  if (fields.handle && link.profile?.handle) account.handle = link.profile.handle;
  if (fields.email && link.profile?.email) account.email = link.profile.email;
  if (fields.name && link.profile?.name) account.name = link.profile.name;
  if (fields.emailVerified) account.emailVerified = Boolean(link.profile?.emailVerified);
  if (fields.verifiedAt) account.verifiedAt = link.linkedAt;

  const credential = {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://byoid.dev/context/v1'],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', 'BYOIDAccountCredential'],
    issuer: state.wallet.did,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: state.wallet.did,
      accounts: [account],
    },
  };
  if (STATIC_MODE && staticBackend) {
    credential.byoidEvidence = [
      { did: state.wallet.did, events: staticBackend.evidenceFor(state.wallet.did) },
    ];
  }
  const signature = await signEs256(state.privateKey, utf8(canonicalize(credential)));
  credential.proof = {
    type: 'JsonWebSignature2020',
    created: new Date().toISOString(),
    verificationMethod: `${state.wallet.did}#key-1`,
    proofPurpose: 'assertionMethod',
    jws: b64url(signature),
  };

  const record = {
    id: credential.id,
    credential,
    issuedAt: credential.issuanceDate,
    provider: link.provider,
    fields: { ...fields },
    demo: Boolean(link.demo),
    revokedAt: null,
    revokeReceipt: null,
  };
  state.wallet.credentials = [record, ...(state.wallet.credentials || [])];
  state.selectedCredentials.add(record.id);
  saveWallet();
  state.modal = null;
  renderAll();
  toast({
    kind: 'ok',
    title: 'Credential signed in your browser',
    message: `${fields.email ? 'Email included' : 'Email not included'} · ${link.provider} · ready to present.`,
  });
}

function buildPresentation(credentials) {
  const presentation = {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://byoid.dev/context/v1'],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiablePresentation', 'BYOIDPresentation'],
    holder: state.wallet.did,
    created: new Date().toISOString(),
    verifiableCredential: credentials.map((record) => record.credential),
  };
  if (STATIC_MODE && staticBackend) {
    // A static verifier cannot read a public rholo name. Carry the issuer's
    // signed event log with the presentation so another browser can run the
    // same reduceEvents() verification offline. The events are signed, so a
    // recipient can reject anything that does not verify.
    presentation.byoidEvidence = [
      { did: state.wallet.did, events: staticBackend.evidenceFor(state.wallet.did) },
    ];
  }
  return presentation;
}

async function presentCredentials(credentials) {
  requireKey();
  if (!credentials.length) {
    toast({ kind: 'warn', title: 'Select at least one credential' });
    return;
  }
  const presentation = buildPresentation(credentials);
  const signature = await signEs256(state.privateKey, utf8(canonicalize(presentation)));
  presentation.proof = {
    type: 'JsonWebSignature2020',
    created: new Date().toISOString(),
    verificationMethod: `${state.wallet.did}#key-1`,
    proofPurpose: 'authentication',
    jws: b64url(signature),
  };
  state.modal = null;
  renderModal();
  setTab('verify');
  await runVerify(presentation);
}

async function presentSelected() {
  const records = (state.wallet?.credentials || []).filter(
    (record) => state.selectedCredentials.has(record.id) && !record.revokedAt && !record.revokedOnChain,
  );
  if (!records.length) {
    toast({ kind: 'warn', title: 'Select a credential first', message: 'Use the checkboxes in your wallet.' });
    return;
  }
  await presentCredentials(records);
}

async function revokeCredential(credentialId) {
  const record = (state.wallet?.credentials || []).find((item) => item.id === credentialId);
  if (!record) return;
  if (record.revokedAt || record.revokedOnChain) {
    toast({ kind: 'warn', title: 'Already revoked' });
    return;
  }
  if (!window.confirm('Revoke this credential on rholo? The credential JSON stays in your wallet, but verifiers will reject it.')) {
    return;
  }
  requireKey();
  try {
    const event = await signNextEvent(EVENT_TYPES.REVOKE, {
      credentialId: record.id,
      revokedAt: new Date().toISOString(),
      reason: 'holder requested',
    });
    const result = await anchorWithRetry(event, 'Revoking the credential');
    record.revokedAt = new Date().toISOString();
    record.revokeEvent = event;
    record.revokeReceipt = result.receipt || null;
    if (result.receipt) recordReceipt(result.receipt);
    if (result.resolution) {
      state.resolution = result.resolution;
      mergeResolutionIntoWallet(result.resolution);
    }
    saveWallet();
    await refreshResolution({ force: true, quiet: true });
    renderAll();
    toast({
      kind: 'ok',
      title: 'Credential revoked',
      message: result.receipt
        ? `Revocation event anchored in block ${result.receipt.blockNumber}.`
        : 'The revocation event is on chain.',
    });
  } catch (error) {
    toast({ kind: 'bad', title: 'Revocation failed', message: error.message });
  }
}

// ── verification ────────────────────────────────────────────────────────────

async function fetchAgent() {
  state.agent = await api('/api/agent');
  return state.agent;
}

async function runVerify(presentation) {
  state.verifier = { status: 'verifying', presentation, result: null, error: null };
  syncPresentationInput();
  renderVerify();
  try {
    if (staticBackend) await staticBackend.ingestEvidence(presentation);
    const agent = state.agent?.publicJwk ? state.agent : await fetchAgent();
    const dids = new Set([
      presentation.holder,
      ...(presentation.verifiableCredential || []).map((credential) => credential?.issuer),
    ].filter(isDid));
    const resolutions = new Map();
    for (const did of dids) {
      const resolution = await fetchResolution(did, { force: true });
      resolutions.set(did, resolution);
    }
    const result = await verifyPresentation({
      presentation,
      resolveDid: async (did) => resolutions.get(did) || fetchResolution(did, { force: true }),
      agentPublicJwk: agent.publicJwk,
      agentKid: agent.kid,
    });
    state.verifier = { status: 'done', presentation, result, error: null };
    renderVerify();
    toast({
      kind: result.ok ? 'ok' : 'bad',
      title: result.ok ? 'Presentation verified' : 'Presentation not verified',
      message: result.ok
        ? 'The holder signature, DID log, attestations and revocation status all check out.'
        : result.errors[0] || 'One or more checks failed.',
    });
  } catch (error) {
    state.verifier = { status: 'error', presentation, result: null, error: error.message };
    renderVerify();
    toast({ kind: 'bad', title: 'Verification failed', message: error.message });
  }
}

async function verifyCredentialOnly(credential) {
  state.verifier = { status: 'verifying', presentation: null, result: null, error: null };
  renderVerify();
  try {
    if (staticBackend) await staticBackend.ingestEvidence(credential);
    const agent = state.agent?.publicJwk ? state.agent : await fetchAgent();
    const issuer = credential.issuer;
    if (!isDid(issuer)) throw new Error('The credential issuer is not a did:byoid identifier.');
    const resolution = await fetchResolution(issuer, { force: true });
    const result = await verifyCredential({
      credential,
      resolution,
      agentPublicJwk: agent.publicJwk,
      agentKid: agent.kid,
    });
    state.verifier = {
      status: 'done',
      presentation: null,
      mode: 'credential',
      credential,
      issuer,
      result: { ...result, holder: issuer, issuer, credentials: [result] },
      error: null,
    };
    renderVerify();
  } catch (error) {
    state.verifier = { status: 'error', presentation: null, result: null, error: error.message };
    renderVerify();
  }
}

async function verifyFromTextarea() {
  const input = $('#presentation-input');
  const raw = input?.value?.trim();
  if (!raw) {
    toast({ kind: 'warn', title: 'Paste a presentation first' });
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    toast({ kind: 'bad', title: 'That is not valid JSON' });
    return;
  }
  if (Array.isArray(parsed?.type) && parsed.type.includes('VerifiablePresentation')) {
    await runVerify(parsed);
    return;
  }
  if (Array.isArray(parsed?.type) && parsed.type.includes('VerifiableCredential')) {
    await verifyCredentialOnly(parsed);
    return;
  }
  toast({
    kind: 'bad',
    title: 'Unknown document',
    message: 'Expected a BYOID VerifiablePresentation or a single VerifiableCredential.',
  });
}

function syncPresentationInput() {
  const input = $('#presentation-input');
  if (!input) return;
  if (document.activeElement === input) return;
  if (state.verifier.presentation) {
    const json = JSON.stringify(state.verifier.presentation, null, 2);
    if (input.value !== json) input.value = json;
  }
}

// ── rendering: header / tabs / stepper ──────────────────────────────────────

function renderHeader() {
  const chainPill = $('#chain-pill');
  const chainText = $('#chain-pill-text');
  const modePill = $('#mode-pill');
  const status = state.chain?.status;
  if (chainPill && chainText) {
    if (status) {
      chainPill.classList.remove('is-offline');
      chainText.textContent = `rholo · ${status.networkId || 'playground'} · #${status.latestBlockNumber ?? '—'}`;
      chainPill.title = `${state.config?.chain?.url || ''}${status.version?.node ? ` · ${status.version.node}` : ''}`;
    } else {
      chainPill.classList.add('is-offline');
      chainText.textContent = 'rholo unreachable';
    }
  }
  if (modePill) {
    const live = (state.config?.providers || []).filter((provider) => provider.mode === 'live').length;
    if (STATIC_MODE) {
      modePill.className = 'pill pill-live';
      modePill.textContent = 'GitHub Pages · live chain';
    } else if (live) {
      modePill.className = 'pill pill-live';
      modePill.textContent = `${live} live provider${live === 1 ? '' : 's'}`;
    } else {
      modePill.className = 'pill pill-demo';
      modePill.textContent = 'demo identities';
    }
  }
  const heroDid = $('#hero-did');
  const heroAnchor = $('#hero-anchor');
  if (heroDid) heroDid.textContent = state.wallet?.did ? shortId(state.wallet.did, 28, 10) : 'did:byoid:z…';
  if (heroAnchor) {
    heroAnchor.textContent = state.wallet?.did
      ? anchorName(state.wallet.did, state.config?.chain?.anchorPrefix || 'byoid')
      : 'byoid:did:z…';
  }
}

function setTab(tab) {
  state.tab = tab;
  localStorage.setItem(TAB_KEY, tab);
  renderTabs();
  if (tab === 'verify') setTimeout(syncPresentationInput, 0);
}

function renderTabs() {
  for (const button of $$('[data-action="tab"]')) {
    const active = button.dataset.tab === state.tab;
    if (button.classList.contains('tab')) {
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-selected', String(active));
    }
  }
  for (const id of ['wallet', 'verify', 'chain']) {
    const view = document.getElementById(`view-${id}`);
    if (view) view.hidden = id !== state.tab;
  }
}

function renderStepper() {
  const root = $('#stepper');
  if (!root) return;
  const wallet = state.wallet;
  const createDone = walletCreateAnchored();
  const linkDone = Boolean(wallet?.links?.some((link) => linkIsAnchored(link)));
  const chainDone = Boolean(
    createDone &&
      state.resolution?.status?.valid &&
      (state.resolution?.events?.length || 0) >= 2 &&
      linkDone,
  );
  const credDone = Boolean(wallet?.credentials?.some((credential) => !credential.revokedAt));
  const done = [createDone, linkDone, chainDone, credDone];
  let active = done.findIndex((value) => !value);
  if (active === -1) active = 3;
  const steps = [
    ['Create DID', 'a key in your browser'],
    ['Connect accounts', 'Google · GitHub · Facebook'],
    ['Anchor on rholo', 'public playground chain'],
    ['Issue a credential', 'sign only what you reveal'],
  ];
  root.innerHTML = steps
    .map(([label, sub], index) => {
      const isDone = done[index];
      const isActive = !isDone && index === active;
      return `
        <div class="step ${isDone ? 'is-done' : ''} ${isActive ? 'is-active' : ''}">
          <span class="step-marker">${isDone ? '✓' : index + 1}</span>
          <span class="step-text">
            <span class="step-label">${esc(label)}</span>
            <span class="step-sub">${esc(sub)}</span>
          </span>
        </div>`;
    })
    .join('');
}

// ── rendering: wallet ───────────────────────────────────────────────────────

function brandIcon(providerId) {
  if (providerId === 'google') {
    return `<svg viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#4285F4" d="M21.6 12.23c0-.71-.06-1.39-.18-2.05H12v3.88h5.38a4.6 4.6 0 0 1-2 3.02v2.51h3.24c1.9-1.75 2.98-4.33 2.98-7.36Z"/>
      <path fill="#34A853" d="M12 22c2.7 0 4.96-.9 6.62-2.42l-3.24-2.51c-.9.6-2.05.96-3.38.96-2.6 0-4.8-1.76-5.59-4.12H3.06v2.59A10 10 0 0 0 12 22Z"/>
      <path fill="#FBBC05" d="M6.41 13.91a6 6 0 0 1 0-3.82V7.5H3.06a10 10 0 0 0 0 9l3.35-2.59Z"/>
      <path fill="#EA4335" d="M12 6.04c1.47 0 2.79.5 3.83 1.5l2.87-2.87A9.6 9.6 0 0 0 12 2a10 10 0 0 0-8.94 5.5l3.35 2.59C7.2 7.8 9.4 6.04 12 6.04Z"/>
    </svg>`;
  }
  if (providerId === 'github') {
    return `<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 2C6.48 2 2 6.58 2 12.26c0 4.53 2.87 8.37 6.84 9.73.5.1.68-.22.68-.49 0-.24-.01-.87-.01-1.71-2.78.62-3.37-1.37-3.37-1.37-.45-1.18-1.11-1.5-1.11-1.5-.91-.64.07-.63.07-.63 1 .07 1.53 1.06 1.53 1.06.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05A9.3 9.3 0 0 1 12 6.84c.85 0 1.7.12 2.5.36 1.91-1.33 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.8-4.57 5.06.36.32.68.94.68 1.9 0 1.37-.01 2.48-.01 2.82 0 .27.18.6.69.49A10.02 10.02 0 0 0 22 12.26C22 6.58 17.52 2 12 2Z"/>
    </svg>`;
  }
  if (providerId === 'facebook') {
    return `<svg viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#1877F2" d="M24 12a12 12 0 1 0-13.88 11.86v-8.39H7.08V12h3.04V9.36c0-3.01 1.79-4.67 4.53-4.67 1.31 0 2.68.23 2.68.23v2.95h-1.51c-1.49 0-1.95.93-1.95 1.88V12h3.32l-.53 3.47h-2.79v8.39A12 12 0 0 0 24 12Z"/>
      <path fill="#fff" d="m16.67 15.47.53-3.47h-3.32V9.75c0-.95.46-1.88 1.95-1.88h1.51V4.92s-1.37-.23-2.68-.23c-2.74 0-4.53 1.66-4.53 4.67V12H7.08v3.47h3.04v8.39a12.1 12.1 0 0 0 3.76 0v-8.39h2.79Z"/>
    </svg>`;
  }
  return `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/></svg>`;
}

function uiIcon(name) {
  const icons = {
    check: '<path d="m5 12.5 4.5 4.5L19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
    copy: '<rect x="9" y="9" width="10" height="10" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3" stroke="currentColor" stroke-width="1.7"/>',
    refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.6M20 4v5h-5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    shield: '<path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6l8-3Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="m8.5 12 2.3 2.3 4.7-4.8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    key: '<circle cx="8" cy="15" r="4" stroke="currentColor" stroke-width="1.7"/><path d="m11 12 8-8m-2 2 2 2m-5 1 2 2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.1 0l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1M14 11a5 5 0 0 0-7.1 0l-2 2A5 5 0 0 0 12 20.1l1.1-1.1" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    download: '<path d="M12 4v11m0 0 4-4m-4 4-4-4M5 19h14" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    upload: '<path d="M12 20V9m0 0 4 4m-4-4-4 4M5 5h14" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    external: '<path d="M14 4h6v6M20 4l-8 8M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    trash: '<path d="M4 7h16M9 7V5h6v2M7 7l1 13h8l1-13M10 11v5m4-5v5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    eye: '<path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" stroke="currentColor" stroke-width="1.7"/><circle cx="12" cy="12" r="2.5" stroke="currentColor" stroke-width="1.7"/>',
    layers: '<path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>',
    server: '<rect x="3.5" y="4" width="17" height="6" rx="2" stroke="currentColor" stroke-width="1.7"/><rect x="3.5" y="14" width="17" height="6" rx="2" stroke="currentColor" stroke-width="1.7"/><circle cx="7" cy="7" r="1" fill="currentColor"/><circle cx="7" cy="17" r="1" fill="currentColor"/>',
  };
  return `<svg class="icon-svg" viewBox="0 0 24 24" fill="none" aria-hidden="true">${icons[name] || icons.link}</svg>`;
}

function avatarHtml(seed, label, { small = false } = {}) {
  let hash = 0;
  for (const char of String(seed || label || '?')) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  const hue = hash % 360;
  const hue2 = (hue + 52) % 360;
  const initials = String(label || seed || '?')
    .split(/[\s.@_-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('');
  return `<span class="avatar ${small ? 'sm' : ''}" style="background:linear-gradient(145deg,hsl(${hue} 58% 42%),hsl(${hue2} 54% 36%))">${esc(initials || '?')}</span>`;
}

function statusBadge(status) {
  if (status === 'demo') return '<span class="badge badge-warn">demo link agent</span>';
  if (status === 'anchored' || status === 'done') return '<span class="badge badge-ok">anchored on rholo</span>';
  if (status === 'error' || status === 'failed') return '<span class="badge badge-err">anchor failed</span>';
  if (status === 'anchoring' || status === 'running') return '<span class="badge badge-accent">anchoring…</span>';
  if (status === 'existing') return '<span class="badge badge-ok">key anchor exists</span>';
  if (status === 'disabled') return '<span class="badge badge-quiet">chain writes off</span>';
  return '<span class="badge badge-warn">local only</span>';
}

function ladder(steps) {
  return `<div class="anchor-ladder">${steps
    .map(
      (step) => `
      <div class="ladder-step is-${esc(step.status)}">
        <span class="marker">${step.status === 'done' ? '✓' : step.status === 'failed' ? '!' : ''}</span>
        <span>${esc(step.label)}</span>
      </div>`,
    )
    .join('')}</div>`;
}

function renderOnboarding() {
  return `
    <div class="card onboarding">
      <div>
        <p class="eyebrow">Start here</p>
        <h2>Your identity begins with a key only you hold.</h2>
        <p>
          BYOID generates a P-256 keypair in this browser and derives a <span class="mono-inline">did:byoid</span>
          identifier from its public half. The private key is stored in IndexedDB and is never sent to the server.
        </p>
        <div class="onboarding-points">
          <div class="onboarding-point"><span class="tick">✓</span><span><strong>One DID.</strong> Google, GitHub, Facebook and Apple become linked personas under it, not separate logins.</span></div>
          <div class="onboarding-point"><span class="tick">✓</span><span><strong>One anchor.</strong> A signed, hash-linked event log lives at a public name on the rholo playground.</span></div>
          <div class="onboarding-point"><span class="tick">✓</span><span><strong>One proof.</strong> Credentials are signed in your browser and disclose only the fields you tick.</span></div>
        </div>
        <div class="onboarding-actions">
          <button class="btn btn-primary" data-action="create-identity">Create my identity</button>
          <button class="btn btn-secondary" data-action="open-import">Import a wallet backup</button>
        </div>
      </div>
      <div class="onboarding-visual" aria-hidden="true">
        <div class="key-illustration">
          <svg viewBox="0 0 24 24" fill="none">
            <circle cx="8.5" cy="15.5" r="4.5" stroke="currentColor" stroke-width="1.3" />
            <path d="m12 12 7.5-7.5m-2.5 2.5 2.2 2.2m-5 1 2.2 2.2" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" />
          </svg>
        </div>
      </div>
    </div>
  `;
}

function renderIdentityCard() {
  const wallet = state.wallet;
  const resolution = state.resolution;
  const createAnchored = walletCreateAnchored();
  const status = createAnchored
    ? 'anchored'
    : wallet.createError
      ? 'error'
      : !state.resolution && wallet.createReceipt
        ? 'anchoring'
        : 'local';
  const block = createAnchored
    ? resolution?.block?.blockNumber || wallet.createReceipt?.blockNumber
    : null;
  const steps = [
    { label: 'Key generated in this browser', status: 'done' },
    { label: 'Create event signed by your DID key', status: wallet.createEvent ? 'done' : 'pending' },
    {
      label: 'Deploy accepted by rholo',
      status: createAnchored ? 'done' : wallet.createError ? 'failed' : 'pending',
    },
    {
      label: 'Included in a block',
      status: createAnchored ? 'done' : wallet.createError ? 'failed' : 'pending',
    },
    {
      label: 'Observed at the DID anchor name',
      status: createAnchored ? 'done' : wallet.createError ? 'failed' : 'pending',
    },
  ];
  const anchorNameValue = anchorName(wallet.did, state.config?.chain?.anchorPrefix || 'byoid');
  return `
    <div class="card identity-card">
      <div class="card-head">
        <div>
          <p class="eyebrow">Step 1 · your self-sovereign identity</p>
          <h2>${createAnchored ? 'Anchored on rholo' : 'Your identity is local'}</h2>
        </div>
        ${statusBadge(status)}
      </div>
      <div class="identity-top">
        ${avatarHtml(wallet.did, 'You')}
        <div class="identity-title">
          <h2>${esc(shortId(wallet.did, 26, 10))}</h2>
          <p>P-256 key · ${esc(wallet.fingerprint || 'fingerprint pending')}</p>
        </div>
      </div>
      <div class="did-box">
        <code>${esc(wallet.did)}</code>
        <button class="copy-btn" data-action="copy-wallet-did" title="Copy DID" aria-label="Copy DID">${uiIcon('copy')}</button>
      </div>
      <div class="meta-grid">
        <div class="meta-item"><span class="label">Anchor name</span><span class="value mono">${esc(anchorNameValue)}</span></div>
        <div class="meta-item"><span class="label">Chain</span><span class="value">${esc(activeNodeLabel())}${block ? ` · block ${esc(block)}` : ''}</span></div>
        <div class="meta-item"><span class="label">Created</span><span class="value">${esc(fmtDate(wallet.createdAt))}</span></div>
        <div class="meta-item"><span class="label">Event log</span><span class="value">${resolution?.status?.valid ? `${resolution.status.eventCount} event(s), seq ${resolution.status.latestSeq}` : 'not yet readable'}</span></div>
      </div>
      ${ladder(steps)}
      ${
        wallet.createError
          ? `<div class="demo-callout" style="background:var(--red-soft);border-color:#ecc5bf;color:var(--red)">Last anchor error: ${esc(wallet.createError)}</div>`
          : ''
      }
      <div class="card-actions">
        ${
          createAnchored
            ? `<button class="btn btn-secondary btn-sm" data-action="refresh-did">${uiIcon('refresh')} Refresh from chain</button>`
            : `<button class="btn btn-primary btn-sm" data-action="retry-create">${uiIcon('layers')} Anchor now</button>`
        }
        <button class="btn btn-ghost btn-sm" data-action="export-wallet">${uiIcon('download')} Export</button>
        <button class="btn btn-ghost btn-sm" data-action="open-import">${uiIcon('upload')} Import</button>
        <button class="btn btn-ghost btn-sm" data-action="new-identity">${uiIcon('key')} New identity</button>
      </div>
    </div>
  `;
}

function renderProviderCard(provider) {
  const link = (state.wallet?.links || []).find((item) => item.provider === provider.id);
  const ready = Boolean(walletCreateAnchored() && state.privateKey && !state.keyError);
  const modeBadge =
    provider.mode === 'live'
      ? '<span class="badge badge-ok">live OAuth</span>'
      : provider.mode === 'demo'
        ? '<span class="badge badge-warn">demo</span>'
        : '<span class="badge badge-quiet">setup needed</span>';
  const anchoredNow = linkIsAnchored(link);
  const receiptHere = receiptMatchesChain(link?.receipt);
  const linkedBlock = link
    ? `<div class="linked-profile">
         ${avatarHtml(link.subjectHash, link.profile?.name || link.profile?.handle || provider.name, { small: true })}
         <div class="linked-profile-text">
           <strong>${esc(link.profile?.handle || link.profile?.email || 'linked account')}</strong>
           <span>${esc(link.profile?.email || link.profile?.name || link.attestationHash.slice(0, 18))}</span>
         </div>
         ${link.demo ? '<span class="badge badge-warn">demo</span>' : '<span class="badge badge-teal">verified</span>'}
       </div>
       <p class="provider-note">
         ${
           anchoredNow
             ? receiptHere
               ? `Link event anchored in block ${esc(link.receipt.blockNumber)}.`
               : `Link event observed on ${esc(activeNodeLabel())}.`
             : link.anchorError
               ? `Anchor error: ${esc(link.anchorError)}`
               : link.receipt
                 ? 'Link event is not present on this rnode; anchor it again.'
                 : 'Link event is waiting for its anchor confirmation.'
         }
       </p>`
    : `<p class="provider-desc">${esc(provider.description)}</p>`;
  const action = link
    ? `<div class="provider-actions">
         <button class="btn btn-secondary btn-sm" data-action="connect-provider" data-provider="${esc(provider.id)}" ${provider.mode === 'unconfigured' ? 'data-unconfigured="1"' : ''}>Reconnect</button>
         ${
           anchoredNow
             ? `<button class="btn btn-ghost btn-sm" data-action="issue-credential-open" data-provider="${esc(provider.id)}">Issue VC</button>`
             : `<button class="btn btn-primary btn-sm" data-action="retry-link" data-provider="${esc(provider.id)}" ${ready ? '' : 'disabled'} title="${ready ? '' : 'Anchor your DID on this rnode first'}">Anchor link</button>`
         }
       </div>`
    : `<button class="btn btn-secondary btn-sm btn-wide" data-action="connect-provider" data-provider="${esc(provider.id)}" ${ready ? '' : 'disabled'} title="${ready ? '' : 'Create and anchor your DID first'}">
         ${provider.mode === 'unconfigured' ? 'Configure provider' : `Connect ${esc(provider.name)}`}
       </button>`;
  return `
    <article class="provider-card ${link ? 'is-linked' : ''}">
      <div class="provider-top">
        <span class="provider-logo">${brandIcon(provider.id)}</span>
        <div class="provider-name">
          <h3>${esc(provider.name)}</h3>
          <p>${esc(provider.kind)}</p>
        </div>
        ${modeBadge}
      </div>
      ${linkedBlock}
      ${action}
    </article>
  `;
}

function renderCredentialCard(record) {
  const summary = credentialSummary(record);
  const provider = providerById(summary.providerId);
  const selected = state.selectedCredentials.has(record.id);
  const disabled = summary.revoked;
  const fieldChips = [
    `<span class="field-chip"><strong>provider:</strong> ${esc(summary.providerId)}</span>`,
    ...summary.fields.map(
      ([field, value]) =>
        `<span class="field-chip"><strong>${esc(fieldLabel(field))}:</strong> ${esc(value)}</span>`,
    ),
    ...summary.hidden.map(
      (field) => `<span class="field-chip is-hidden">${esc(fieldLabel(field))}: not included</span>`,
    ),
  ].join('');
  return `
    <article class="credential-card ${selected ? 'is-selected' : ''} ${summary.revoked ? 'is-revoked' : ''}">
      <div class="cred-check">
        <input class="check" type="checkbox" data-action="toggle-credential" data-credential-id="${esc(record.id)}" ${selected ? 'checked' : ''} ${disabled ? 'disabled' : ''} aria-label="Select credential for presentation" />
      </div>
      <div class="cred-main">
        <div class="cred-title">
          <span class="provider-logo" style="width:28px;height:28px;border-radius:8px">${brandIcon(summary.providerId)}</span>
          <strong>${esc(provider?.name || summary.providerId)} account</strong>
          ${record.demo ? '<span class="badge badge-warn">demo</span>' : ''}
          ${summary.revoked ? '<span class="badge badge-err">revoked</span>' : '<span class="badge badge-ok">active</span>'}
        </div>
        <div class="cred-fields">${fieldChips}</div>
        <div class="cred-id">${esc(record.id)} · issued ${esc(fmtDate(summary.issuedAt, { short: true }))}</div>
      </div>
      <div class="cred-actions">
        <button class="btn btn-ghost btn-sm" data-action="copy-credential" data-credential-id="${esc(record.id)}">Copy</button>
        ${
          summary.revoked
            ? ''
            : `<button class="btn btn-ghost btn-sm" data-action="revoke-credential" data-credential-id="${esc(record.id)}">Revoke</button>`
        }
      </div>
    </article>
  `;
}

function renderActivity() {
  const receipts = (state.wallet?.receipts || [])
    .filter((receipt) => receiptMatchesChain(receipt))
    .sort((a, b) => Date.parse(b.confirmedAt || 0) - Date.parse(a.confirmedAt || 0));
  if (!receipts.length) {
    return `<div class="empty-card" style="padding:22px"><div class="empty-icon">◌</div><h3>No chain writes yet</h3><p>Your first deploy will appear here with its block and deploy id.</p></div>`;
  }
  return `<div class="activity-list">${receipts
    .slice(0, 8)
    .map((receipt) => {
      const type = receipt.eventType || 'anchor';
      const icon = type === EVENT_TYPES.CREATE ? 'key' : type === EVENT_TYPES.LINK ? 'link' : 'shield';
      const tone = type === EVENT_TYPES.CREATE ? 'info' : 'ok';
      return `
        <div class="activity-item">
          <span class="activity-icon ${tone}">${uiIcon(icon)}</span>
          <div class="activity-body">
            <strong>${esc(eventTypeLabel(type))}</strong>
            <span>block ${esc(receipt.blockNumber ?? '—')} · deploy ${esc(shortId(receipt.deployId, 12, 8))} · ${esc(fmtRelative(receipt.confirmedAt))}</span>
          </div>
          <button class="activity-link" data-action="tab" data-tab="chain">evidence</button>
        </div>`;
    })
    .join('')}</div>`;
}

function renderWallet() {
  const root = $('#wallet-root');
  if (!root) return;
  if (!state.wallet) {
    root.innerHTML = `
      ${renderOnboarding()}
      <div class="section-title-row">
        <div><p class="section-kicker">Then</p><h2>Bring your own accounts</h2></div>
        <span class="badge badge-quiet">locked until you create a DID</span>
      </div>
      <div class="provider-grid">${(state.config?.providers || []).map(renderProviderCard).join('')}</div>
      <div class="section-title-row"><div><p class="section-kicker">Why</p><h2>One anchor, many personas</h2></div></div>
      <div class="grid grid-2">
        <div class="info-box"><h4>On rholo</h4><ul><li>The DID public key and service endpoint</li><li>Hashes of each linked provider subject and attestation</li><li>Credential revocation events</li><li>Nothing else</li></ul></div>
        <div class="info-box"><h4>In your browser</h4><ul><li>The private key (IndexedDB)</li><li>Provider handles, names and emails</li><li>Signed credentials you choose to keep</li><li>The presentation you choose to share</li></ul></div>
      </div>
    `;
    return;
  }

  const wallet = state.wallet;
  const keyWarning =
    state.keyError || !state.privateKey
      ? `<div class="demo-callout" style="background:var(--red-soft);border-color:#ecc5bf;color:var(--red)">
           <strong>Signing key unavailable.</strong> ${esc(state.keyError || 'This browser does not have the wallet key.')}
           <button class="link-btn" data-action="open-import" style="margin-left:6px">Import your backup</button>
         </div>`
      : '';
  const createWarning =
    !walletCreateAnchored() && !wallet.createError
      ? `<div class="demo-callout"><strong>Your DID is local.</strong> Anchor it before connecting accounts; the link event extends the on-chain log.</div>`
      : '';
  const links = wallet.links || [];
  const activeCredentials = (wallet.credentials || []).filter(
    (record) => !record.revokedAt && !record.revokedOnChain,
  );
  const selectedCount = (wallet.credentials || []).filter(
    (record) => state.selectedCredentials.has(record.id) && !record.revokedAt && !record.revokedOnChain,
  ).length;
  root.innerHTML = `
    ${keyWarning}
    ${createWarning}
    <div class="grid grid-wallet">
      ${renderIdentityCard()}
      <div class="stack">
        <div class="card">
          <div class="card-head">
            <div><p class="eyebrow">Step 2 · bring your accounts</p><h2>Providers</h2></div>
            <span class="badge ${links.length ? 'badge-ok' : 'badge-quiet'}">${links.length}/3 linked</span>
          </div>
          <p class="card-lede">An OAuth sign-in proves you control the account. The agent signs a hash-only attestation; only the hash and link event go on rholo.</p>
          <div class="provider-grid">${(state.config?.providers || []).map(renderProviderCard).join('')}</div>
        </div>
        <div class="card">
          <div class="card-head">
            <div><p class="eyebrow">Evidence</p><h2>Recent chain writes</h2></div>
            <button class="btn btn-ghost btn-sm" data-action="tab" data-tab="chain">${uiIcon('external')} All evidence</button>
          </div>
          ${renderActivity()}
        </div>
      </div>
    </div>

    <div class="section-title-row">
      <div><p class="section-kicker">Step 4 · prove only what you choose</p><h2>Your credentials</h2></div>
      <div class="card-actions">
        <button class="btn btn-secondary btn-sm" data-action="issue-credential-open" data-provider="${esc(links[0]?.provider || '')}" ${links.length ? '' : 'disabled'}>${uiIcon('key')} Issue credential</button>
        <button class="btn btn-accent btn-sm" data-action="present-selected" ${selectedCount ? '' : 'disabled'}>${uiIcon('shield')} Present selected${selectedCount ? ` (${selectedCount})` : ''}</button>
      </div>
    </div>
    ${
      (wallet.credentials || []).length
        ? `<div class="credential-list">${wallet.credentials.map(renderCredentialCard).join('')}</div>`
        : `<div class="card empty-card">
             <div class="empty-icon">◇</div>
             <h3>No credentials yet</h3>
             <p>Issue a credential from a linked account. Choose whether the verifier sees your handle, email, email-verification flag and verification date. The signature covers only what you include.</p>
             <button class="btn btn-primary btn-sm" data-action="issue-credential-open" data-provider="${esc(links[0]?.provider || '')}" ${links.length ? '' : 'disabled'}>Issue my first credential</button>
           </div>`
    }
    ${
      activeCredentials.length && selectedCount
        ? `<p class="small muted" style="margin-top:10px">${selectedCount} credential(s) selected. The presentation is signed in your browser; nothing is uploaded.</p>`
        : ''
    }
  `;
}

// ── rendering: verify ───────────────────────────────────────────────────────

function renderChecks(checks) {
  if (!checks?.length) return '';
  return `<div class="checks">${checks
    .map(
      (check) => `
      <div class="check-row ${check.ok ? 'ok' : 'bad'}">
        <span class="check-mark">${check.ok ? '✓' : '!'}</span>
        <span class="check-text"><strong>${esc(check.label)}</strong><span>${esc(check.detail || '')}</span></span>
      </div>`,
    )
    .join('')}</div>`;
}

function renderClaim(claim) {
  return `
    <div class="claim-card">
      <div class="claim-head">
        <span class="provider-logo" style="width:26px;height:26px;border-radius:8px">${brandIcon(claim.provider)}</span>
        <strong>${esc(claim.provider)}</strong>
        ${claim.demo ? '<span class="badge badge-warn">demo</span>' : '<span class="badge badge-teal">verified link</span>'}
      </div>
      ${claim.handle ? `<div class="claim-row"><span>Handle</span><span>${esc(claim.handle)}</span></div>` : ''}
      ${claim.email ? `<div class="claim-row"><span>Email</span><span>${esc(claim.email)}</span></div>` : ''}
      <div class="claim-row"><span>Email verified</span><span>${claim.emailVerified ? 'yes' : 'not asserted'}</span></div>
      <div class="claim-row"><span>Linked at</span><span>${esc(fmtDate(claim.verifiedAt))}</span></div>
      ${
        claim.hiddenFields?.length
          ? `<div class="claim-hidden">${claim.hiddenFields
              .map((field) => `<span class="field-chip is-hidden">${esc(fieldLabel(field))}: not disclosed</span>`)
              .join('')}</div>`
          : ''
      }
    </div>
  `;
}

function renderVerificationResult() {
  const verifier = state.verifier;
  if (verifier.status === 'idle') {
    return `
      <div class="card empty-card">
        <div class="empty-icon">◎</div>
        <h3>Nothing verified yet</h3>
        <p>A verified presentation will show a green banner, every check that passed, and the exact claims the holder chose to reveal.</p>
        <button class="btn btn-ghost btn-sm" data-action="open-help">What does the verifier check?</button>
      </div>`;
  }
  if (verifier.status === 'verifying') {
    return `
      <div class="card">
        <div class="verdict pending"><div class="verdict-icon">…</div><div><h3>Verifying</h3><p>Resolving the issuer DID from rholo and checking signatures, attestations and revocations.</p></div></div>
        <div class="skeleton skeleton-line"></div><div class="skeleton skeleton-line short"></div>
      </div>`;
  }
  if (verifier.status === 'error') {
    return `
      <div class="card">
        <div class="verdict bad"><div class="verdict-icon">!</div><div><h3>Could not verify</h3><p>${esc(verifier.error)}</p></div></div>
        <button class="btn btn-secondary btn-sm" data-action="verify-paste">Try again</button>
      </div>`;
  }

  const result = verifier.result;
  const presentation = verifier.presentation;
  const isCredentialOnly = verifier.mode === 'credential';
  const credentialResults = result?.credentials || [];
  const allClaims = credentialResults.flatMap((credential) => credential.claims || []);
  const failedChecks = (result?.checks || []).filter((check) => !check.ok);
  const issuerDids = [...new Set((presentation?.verifiableCredential || []).map((credential) => credential.issuer))];
  if (isCredentialOnly && verifier.issuer) issuerDids.push(verifier.issuer);
  const resolutions = issuerDids.map((did) => state.didCache.get(did)).filter(Boolean);
  const block = resolutions[0]?.block?.blockNumber || state.resolution?.block?.blockNumber;
  const linkEvents = resolutions.flatMap((resolution) => resolution.links || []);
  return `
    <div class="card">
      <div class="verdict ${result.ok ? 'ok' : 'bad'}">
        <div class="verdict-icon">${result.ok ? '✓' : '!'}</div>
        <div>
          <h3>${result.ok ? 'Verified' : 'Not verified'}</h3>
          <p>${
            result.ok
              ? isCredentialOnly
                ? 'The credential signature, issuer DID log and each provider attestation check out.'
                : 'The holder signature, issuer DID log, each provider attestation and the revocation list check out.'
              : esc(result.errors?.[0] || failedChecks[0]?.detail || 'One or more checks failed.')
          }</p>
        </div>
      </div>
      <div class="section-subhead"><h4>Checks</h4><span class="badge ${result.ok ? 'badge-ok' : 'badge-err'}">${(result.checks || []).filter((check) => check.ok).length}/${(result.checks || []).length} passed</span></div>
      ${renderChecks(result.checks)}
      ${
        failedChecks.length
          ? `<details class="raw-details" open><summary>Why it failed</summary><pre class="code-block light">${esc(
              (result.errors || []).join('\n') || failedChecks.map((check) => `${check.label}: ${check.detail}`).join('\n'),
            )}</pre></details>`
          : ''
      }
      ${
        allClaims.length
          ? `<div class="section-subhead"><h4>What the verifier learned</h4><span class="badge badge-accent">${allClaims.length} disclosed account(s)</span></div>
             <div class="claims-table">${allClaims.map(renderClaim).join('')}</div>`
          : ''
      }
      ${
        !result.ok && credentialResults.some((credential) => credential.checks?.length)
          ? `<details class="raw-details"><summary>Credential-level checks</summary>${credentialResults
              .map((credential, index) => `<div class="section-subhead"><h4>Credential ${index + 1}</h4></div>${renderChecks(credential.checks)}`)
              .join('')}</details>`
          : ''
      }
      <div class="section-subhead"><h4>Evidence</h4><span class="badge badge-quiet">${esc(activeNodeLabel())}</span></div>
      <div class="chain-status-list">
        ${issuerDids
          .map(
            (did) => `
          <div class="chain-status-row"><span>Issuer DID</span><span>${esc(shortId(did, 26, 10))}</span></div>`,
          )
          .join('')}
        <div class="chain-status-row"><span>Resolved at block</span><span>${esc(block ?? '—')}</span></div>
        <div class="chain-status-row"><span>Agent key</span><span>${esc(state.agent?.fingerprint || '—')}</span></div>
        <div class="chain-status-row"><span>Link events</span><span>${esc(linkEvents.length ? linkEvents.map((link) => `seq ${link.seq} · ${link.provider}`).join(', ') : '—')}</span></div>
      </div>
      <div class="card-actions" style="margin-top:12px">
        <button class="btn btn-secondary btn-sm" data-action="copy-proof">${uiIcon('copy')} Copy proof JSON</button>
        <button class="btn btn-ghost btn-sm" data-action="download-proof">${uiIcon('download')} Download</button>
        <button class="btn btn-ghost btn-sm" data-action="copy-share-link">${uiIcon('link')} Copy share link</button>
      </div>
      <details class="raw-details"><summary>Raw ${isCredentialOnly ? 'credential' : 'presentation'} JSON</summary><pre class="code-block">${esc(
        JSON.stringify(presentation || verifier.credential || result, null, 2),
      )}</pre></details>
    </div>
  `;
}

function renderVerify() {
  const root = $('#verify-result');
  if (!root) return;
  root.innerHTML = renderVerificationResult();
  syncPresentationInput();
}

// ── rendering: chain evidence ───────────────────────────────────────────────

function renderChainEvent(event) {
  const receipt = findReceipt(event.id);
  const receiptHtml = receipt
    ? `<div class="event-meta-grid">
         <div class="event-meta"><span class="label">Deploy id</span><span class="value">${esc(shortId(receipt.deployId, 18, 10))}</span></div>
         <div class="event-meta"><span class="label">Block</span><span class="value">${esc(receipt.blockNumber)}</span></div>
         <div class="event-meta"><span class="label">State hash</span><span class="value">${esc(shortId(receipt.stateHash || receipt.blockHash || '', 22, 10))}</span></div>
         <div class="event-meta"><span class="label">Confirmed</span><span class="value">${esc(fmtDate(receipt.confirmedAt))}</span></div>
       </div>
       <div class="card-actions">
         <a class="btn btn-ghost btn-sm" href="${STATIC_MODE ? 'https://playground.rhobot.net/api/v1/deploy-status' : '/api/chain/deploy'}/${encodeURIComponent(receipt.deployId)}" target="_blank" rel="noreferrer">${uiIcon('external')} deploy status</a>
         <a class="btn btn-ghost btn-sm" href="${STATIC_MODE ? 'https://playground.rhobot.net/api/v1/block' : '/api/chain/block'}/${encodeURIComponent(receipt.blockHash)}" target="_blank" rel="noreferrer">${uiIcon('external')} block JSON</a>
       </div>`
    : `<p class="small muted">This event is in the canonical chain, but this browser does not have its deploy receipt. It may have been written from another device.</p>`;
  return `
    <details class="event-item">
      <summary class="event-summary">
        <span class="event-seq">${esc(event.seq)}</span>
        <span class="event-main">
          <strong>${esc(eventTypeLabel(event.type))}</strong>
          <span>${esc(fmtDate(event.at))} · ${esc(shortId(event.id, 20, 10))}</span>
        </span>
        <span class="badge badge-ok">on chain</span>
      </summary>
      <div class="event-body">
        ${receiptHtml}
        <details class="raw-details"><summary>Signed event JSON</summary><pre class="code-block light">${esc(JSON.stringify(event, null, 2))}</pre></details>
      </div>
    </details>
  `;
}

function renderProofItem(proof) {
  const provider = providerById(proof.provider);
  const url = accountUrl(proof.provider, proof.handle);
  const handle = proof.handle || 'hash-only proof';
  return `
    <article class="proof-item">
      <div class="proof-item-main">
        <span class="proof-provider">${esc(provider?.name || proof.provider)}</span>
        ${proof.demo ? '<span class="badge badge-warn">demo</span>' : '<span class="badge badge-teal">verified</span>'}
        <strong>${url ? `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(handle)}</a>` : esc(handle)}</strong>
      </div>
      <div class="proof-item-meta">
        <span>attestation ${esc(shortId(proof.attestationHash || '', 18, 10))}</span>
        <span>link ${esc(shortId(proof.linkEventId || '', 18, 10))}</span>
        <span>${esc(fmtDate(proof.linkedAt))}</span>
      </div>
    </article>
  `;
}

function renderProofChecks(checks) {
  return `
    <details class="proof-checks">
      <summary>${checks.filter((check) => check.ok).length}/${checks.length} checks passed</summary>
      <ul>
        ${checks
          .map(
            (check) => `
          <li class="${check.ok ? 'is-ok' : 'is-bad'}">
            <span class="proof-check-icon">${check.ok ? '✓' : '!'}</span>
            <span><strong>${esc(check.label)}</strong>${check.detail ? ` <span class="muted">${esc(check.detail)}</span>` : ''}</span>
          </li>`,
          )
          .join('')}
      </ul>
    </details>
  `;
}

function renderProofLookupResult() {
  const lookup = state.proofLookup;
  if (!lookup || lookup.status === 'idle') {
    return `<div class="proof-empty">Enter a REV address to read its public proof card, or a DID to inspect its hash-only account links.</div>`;
  }
  if (lookup.status === 'loading') {
    return `<div class="proof-empty"><span class="spinner"></span> Reading proofs from rholo…</div>`;
  }
  if (lookup.status === 'error') {
    return `<div class="progress-error">${esc(lookup.error)}</div>`;
  }
  const result = lookup.result;
  if (!result) return '';
  if (result.kind === 'did') {
    const resolution = result.resolution;
    const links = resolution?.links || [];
    if (!resolution?.status?.valid) {
      return `<div class="progress-error">The DID log is not valid on this rnode: ${esc((resolution?.status?.errors || []).join(' · ') || 'not found')}</div>`;
    }
    return `
      <div class="proof-result">
        <div class="proof-result-head">
          <div><span class="field-label">DID proof index</span><strong class="mono">${esc(result.did)}</strong></div>
          <span class="badge badge-ok">${links.length} anchored link(s)</span>
        </div>
        ${
          links.length
            ? `<div class="proof-list">${links
                .map(
                  (link) => `
              <article class="proof-item">
                <div class="proof-item-main">
                  <span class="proof-provider">${esc(providerById(link.provider)?.name || link.provider)}</span>
                  <strong>${esc(shortId(link.subjectHash, 18, 10))}</strong>
                </div>
                <div class="proof-item-meta">
                  <span>attestation ${esc(shortId(link.attestationHash, 18, 10))}</span>
                  <span>${esc(fmtDate(link.linkedAt))}</span>
                </div>
              </article>`,
                )
                .join('')}</div>`
            : '<div class="proof-empty">This DID has no provider links in its canonical log.</div>'
        }
        <p class="small muted">DID logs publish only hashes. Publish a REV proof card to disclose provider handles with verifiable attestations.</p>
      </div>
    `;
  }
  if (result.kind === 'rev') {
    if (!result.cards.length) {
      return `<div class="proof-empty">No BYOID proof card is anchored at <span class="mono-inline">${esc(result.name)}</span> on this rnode yet.</div>`;
    }
    if (!result.valid) {
      const reasons = result.verified.flatMap((item) => item.errors || []).slice(0, 8);
      return `
        <div class="proof-result">
          <div class="proof-result-head">
            <div><span class="field-label">REV proof card</span><strong class="mono">${esc(result.address)}</strong></div>
            <span class="badge badge-bad">invalid</span>
          </div>
          <div class="progress-error">No card at this address passed verification.</div>
          ${reasons.length ? `<ul class="proof-error-list">${reasons.map((reason) => `<li>${esc(reason)}</li>`).join('')}</ul>` : ''}
          <p class="small muted">${result.cards.length} candidate card(s); ${result.invalidValues.length} malformed value(s).</p>
        </div>
      `;
    }
    const card = result.valid.card;
    const block = result.valid.resolution?.block || result.block;
    return `
      <div class="proof-result">
        <div class="proof-result-head">
          <div>
            <span class="field-label">REV proof card · verified</span>
            <strong class="mono">${esc(result.address)}</strong>
            <span class="small muted proof-did">DID ${esc(card.did)}</span>
          </div>
          <span class="badge badge-ok">${result.valid.proofs.length} proof${result.valid.proofs.length === 1 ? '' : 's'}</span>
        </div>
        <div class="proof-card-meta">
          <span><strong>Network</strong> ${esc(card.network || '—')}</span>
          <span><strong>Issued</strong> ${esc(fmtDate(card.issuedAt))}</span>
          <span><strong>Block</strong> ${esc(block?.blockNumber ?? '—')}</span>
          <span><strong>DID log</strong> ${esc(card.did)}</span>
        </div>
        <div class="proof-list">${result.valid.proofs.map(renderProofItem).join('')}</div>
        ${renderProofChecks(result.valid.checks)}
        <p class="small muted">The REV key signed this card and its address derives from that key. The DID key signed the same card, and every provider attestation matches an anchored link event.</p>
      </div>
    `;
  }
  return '';
}

function renderProofPublisher() {
  const key = state.revKey;
  const links = anchoredProofLinks();
  const canPublish = Boolean(state.wallet && state.privateKey && walletCreateAnchored() && links.length);
  const hasPublished = Boolean(state.wallet?.revProof?.receipt);
  return `
    <div class="card proof-publisher">
      <div class="card-head">
        <div><p class="eyebrow">Public proofs · Keybase-style</p><h2>Publish a REV proof address</h2></div>
        ${key ? '<span class="badge badge-ok">REV key ready</span>' : '<span class="badge badge-quiet">created on publish</span>'}
      </div>
      <p class="card-lede">A REV proof card binds a secp256k1 REV address to your DID and lists the provider handles you choose to disclose. It is signed by both keys and anchored on the selected rholo network.</p>
      ${
        key
          ? `<div class="proof-address"><code>${esc(key.address)}</code><button class="btn btn-ghost btn-sm" data-action="copy-rev-address">${uiIcon('copy')} Copy</button></div>`
          : '<div class="proof-empty">A REV proof key will be generated in this browser when you publish.</div>'
      }
      <div class="proof-publish-row">
        <span class="small muted">${links.length} anchored provider proof${links.length === 1 ? '' : 's'}. Publishing reveals these handles publicly; attestations contain hashes only.</span>
        <button class="btn btn-primary btn-sm" data-action="publish-rev-proofs" ${canPublish ? '' : 'disabled'}>
          ${uiIcon('layers')} ${hasPublished ? 'Refresh REV proof card' : 'Publish REV proof card'}
        </button>
      </div>
      ${!links.length && state.wallet ? '<p class="small muted">Connect and anchor at least one provider first.</p>' : ''}
      <p class="small muted">Rholang index: <span class="mono-inline">byoid:rev:registry</span> · direct lookup name: <span class="mono-inline">byoid:rev:&lt;address&gt;</span>.</p>
    </div>
  `;
}

function renderProofLookup() {
  const key = state.revKey;
  return `
    <div class="card proof-lookup">
      <div class="card-head">
        <div><p class="eyebrow">Proof lookup</p><h2>Proofs by REV address</h2></div>
        <span class="badge badge-quiet">Keybase-style directory</span>
      </div>
      <p class="card-lede">Query a REV address to see the public proofs bound to it, or query a DID to inspect its hash-only account links. Results are verified from the selected rnode, not trusted from the lookup name.</p>
      <div class="proof-search-row">
        <input id="proof-query" class="node-input" value="${esc(state.proofQuery || '')}" placeholder="REV address or did:byoid:…" autocomplete="off" spellcheck="false" />
        <button class="btn btn-primary" data-action="lookup-proofs">Look up proofs</button>
        ${key ? '<button class="btn btn-ghost" data-action="use-my-rev-address">My address</button>' : ''}
      </div>
      ${renderProofLookupResult()}
    </div>
  `;
}

function renderChain() {
  const root = $('#chain-root');
  if (!root) return;
  const chain = state.chain;
  const status = chain?.status;
  const caps = chain?.capabilities;
  const resolution = state.resolution;
  const wallet = state.wallet;
  const anchorNameValue = wallet
    ? anchorName(wallet.did, state.config?.chain?.anchorPrefix || 'byoid')
    : null;
  const events = resolution?.events || [];
  const sampleEvent = wallet?.createEvent || events[0] || null;
  const sampleValue = sampleEvent ? b64url(utf8(JSON.stringify(sampleEvent))) : '';
  const sampleTerm = anchorNameValue && sampleValue ? `@"${anchorNameValue}"!("${sampleValue}")` : '';
  root.innerHTML = `
    <div class="chain-grid">
      <div class="card stat-card">
        <span class="stat-label">Endpoint</span>
        <span class="stat-value">${esc(chain?.url || state.config?.chain?.url || '—')}</span>
        <span class="stat-sub">${esc(status?.version?.node || (chain?.errors?.[0] || 'not reachable'))}</span>
      </div>
      <div class="card stat-card">
        <span class="stat-label">Network / shard</span>
        <span class="stat-value">${esc(status?.networkId || '—')} <span class="muted">·</span> ${esc(status?.shardId || '—')}</span>
        <span class="stat-sub">${status ? `latest block ${status.latestBlockNumber} · ${status.proposeOnDeploy ? 'propose on deploy' : 'manual propose'}` : 'status unavailable'}</span>
      </div>
      <div class="card stat-card">
        <span class="stat-label">Dev surfaces</span>
        <span class="stat-value">${caps ? (caps.devMode ? 'dev-mode' : 'production mode') : '—'}</span>
        <span class="stat-sub">${caps ? `faucet ${caps.faucet ? 'available' : 'off'}${caps.faucetRemaining !== undefined ? ` · ${(Number(caps.faucetRemaining) / 1e8).toFixed(2)} REV left` : ''}` : 'capabilities unavailable'}</span>
      </div>
    </div>

    <div class="grid grid-2" style="margin-bottom:16px">
      <div class="card">
        <div class="card-head">
          <div><p class="eyebrow">Link agent</p><h2>Attestation key</h2></div>
          ${statusBadge(state.agent?.chainAnchor?.status || 'idle')}
        </div>
        <p class="card-lede">${STATIC_MODE ? 'This browser-only build embeds a public demo link-agent key. It signs hash-only demo attestations; the DID event log itself is anchored live on the rholo playground.' : `The agent verifies provider profiles and signs hash-only attestations. Its public key is self-signed and published once at <span class="mono-inline">${esc(state.config?.chain?.agentName || 'byoid:agent:key')}</span>.`}</p>
        <div class="chain-status-list">
          <div class="chain-status-row"><span>Fingerprint</span><span>${esc(state.agent?.fingerprint || '—')}</span></div>
          <div class="chain-status-row"><span>Issuer / kid</span><span>${esc(state.agent?.issuer || '—')} · ${esc(state.agent?.kid || '—')}</span></div>
          ${
            STATIC_MODE
              ? '<div class="chain-status-row"><span>Mode</span><span>embedded demo key</span></div>'
              : `<div class="chain-status-row"><span>Anchor block</span><span>${esc(state.agent?.chainAnchor?.blockNumber ?? '—')}</span></div>
          <div class="chain-status-row"><span>Anchor deploy</span><span>${esc(shortId(state.agent?.chainAnchor?.deployId || '', 18, 10) || '—')}</span></div>`
          }
        </div>
        ${
          state.agent?.chainAnchor?.status === 'error'
            ? `<div class="progress-error">${esc(state.agent.chainAnchor.error || 'agent anchor failed')}</div>`
            : ''
        }
        <div class="card-actions" style="margin-top:12px">
          ${STATIC_MODE ? '' : `<button class="btn btn-secondary btn-sm" data-action="anchor-agent">${uiIcon('layers')} Publish / refresh key</button>`}
          <button class="btn btn-ghost btn-sm" data-action="refresh-chain">${uiIcon('refresh')} Refresh chain</button>
        </div>
      </div>
      <div class="card">
        <div class="card-head">
          <div><p class="eyebrow">Your DID</p><h2>Anchor status</h2></div>
          ${wallet ? statusBadge(walletCreateAnchored() ? 'anchored' : wallet.createError ? 'error' : !state.resolution && wallet.createReceipt ? 'anchoring' : 'local') : '<span class="badge badge-quiet">no wallet</span>'}
        </div>
        ${
          wallet
            ? `<div class="chain-status-list">
                 <div class="chain-status-row"><span>DID</span><span>${esc(shortId(wallet.did, 28, 12))}</span></div>
                 <div class="chain-status-row"><span>Anchor name</span><span>${esc(anchorNameValue)}</span></div>
                 <div class="chain-status-row"><span>Canonical events</span><span>${esc(resolution?.status?.eventCount ?? 0)}</span></div>
                 <div class="chain-status-row"><span>Latest sequence</span><span>${esc(resolution?.status?.latestSeq ?? 0)}</span></div>
                 <div class="chain-status-row"><span>Rejected / forked</span><span>${esc(resolution?.status?.rejectedCount ?? 0)} / ${resolution?.status?.forked ? 'yes' : 'no'}</span></div>
                 <div class="chain-status-row"><span>Read at block</span><span>${esc(resolution?.block?.blockNumber ?? '—')}</span></div>
               </div>
               ${resolution?.status?.errors?.length ? `<div class="progress-error">${esc(resolution.status.errors.join(' · '))}</div>` : ''}
               <div class="card-actions" style="margin-top:12px">
                 <button class="btn btn-secondary btn-sm" data-action="refresh-did">${uiIcon('refresh')} Refresh DID log</button>
                 <button class="btn btn-ghost btn-sm" data-action="open-node-picker">${uiIcon('server')} Change rnode</button>
                 <button class="btn btn-ghost btn-sm" data-action="copy-wallet-did">${uiIcon('copy')} Copy DID</button>
               </div>`
            : `<div class="empty-card"><div class="empty-icon">◌</div><h3>No identity in this browser</h3><p>Create one to see its signed event log.</p><button class="btn btn-primary btn-sm" data-action="create-identity">Create my identity</button></div>`
        }
      </div>
    </div>

    ${renderProofLookup()}
    ${renderProofPublisher()}

    <div class="card">
      <div class="card-head">
        <div><p class="eyebrow">The audit trail</p><h2>Signed event log</h2></div>
        <span class="badge badge-quiet">${events.length} canonical event(s)</span>
      </div>
      <p class="card-lede">Each event is signed by the DID key and points at the previous event id. The chain is read back from a public tuple-space name; the app rejects invalid signatures, gaps and forks rather than trusting whatever is written there.</p>
      ${events.length ? `<div class="event-list">${events.map(renderChainEvent).join('')}</div>` : `<div class="empty-card" style="padding:24px"><div class="empty-icon">◌</div><h3>No events on chain yet</h3><p>${wallet ? 'Anchor your DID to start the log.' : 'Create an identity first.'}</p></div>`}
    </div>

    <div class="section-title-row"><div><p class="section-kicker">How the anchor is written</p><h2>The actual Rholang</h2></div></div>
    <div class="card">
      <p class="card-lede">A public name receives one base64url-encoded JSON event. No quoting or escaping is needed inside the string, so the term is exactly this shape:</p>
      <pre class="code-block">${esc(sampleTerm || '@"byoid:did:z…"!("<base64url event>")')}</pre>
      <details class="raw-details"><summary>Decoded event</summary><pre class="code-block">${esc(JSON.stringify(sampleEvent || { note: 'create an identity to see a signed event' }, null, 2))}</pre></details>
    </div>

    <div class="info-split" style="margin-top:16px">
      <div class="info-box">
        <h4>What the chain proves</h4>
        <ul>
          <li>The DID's create event is signed by its own key.</li>
          <li>Every later event is signed by that key and hash-linked to its predecessor.</li>
          <li>A link event commits to the hash of the agent attestation.</li>
          <li>A revocation event names the credential id, so verifiers can reject it.</li>
        </ul>
      </div>
      <div class="info-box">
        <h4>What the chain does not contain</h4>
        <ul>
          <li>No handles, names or email addresses.</li>
          <li>No OAuth access tokens or client secrets.</li>
          <li>No private keys — the wallet key never leaves the browser.</li>
          <li>No credential contents unless you choose to share them off-chain.</li>
        </ul>
      </div>
    </div>
    ${chain?.errors?.length ? `<p class="small muted" style="margin-top:12px">Chain observations: ${esc(chain.errors.join(' · '))}</p>` : ''}
  `;
}

// ── rendering: modals ───────────────────────────────────────────────────────

function nodeGroups(nodes) {
  const groups = new Map();
  for (const node of nodes) {
    const group = node.group || 'Other';
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(node);
  }
  return groups;
}

function renderNodeForm(draft) {
  return `
    <div class="modal-backdrop" data-action="close-modal">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="node-form-title">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Custom rnode</p>
            <h2 id="node-form-title">${draft.id ? 'Edit node' : 'Add a node'}</h2>
          </div>
          <button class="modal-close" data-action="cancel-rnode-edit" aria-label="Back">×</button>
        </div>
        <p class="card-lede">Custom nodes are stored only in this browser. The URL and port must point at an rholo / rnode HTTP API.</p>
        <div class="node-form">
          <label>
            <span class="field-label">Node name</span>
            <input id="rnode-name" class="node-input" value="${esc(draft.name || '')}" placeholder="My rnode" autocomplete="off" />
          </label>
          <label>
            <span class="field-label">Node URL</span>
            <input id="rnode-url" class="node-input" value="${esc(draft.url || '')}" placeholder="https://rnode.example.net" autocomplete="off" spellcheck="false" />
          </label>
          <label>
            <span class="field-label">Port (optional)</span>
            <input id="rnode-port" class="node-input" value="${esc(draft.port ?? '')}" placeholder="40403" inputmode="numeric" autocomplete="off" />
          </label>
        </div>
        <p class="modal-note">Leave the port blank when the URL already includes one. Selecting a node changes the chain BYOID reads and writes; it does not copy your DID anchors to that chain.</p>
        <div class="modal-actions">
          <button class="btn btn-ghost" data-action="cancel-rnode-edit">Back</button>
          <button class="btn btn-primary" data-action="save-rnode">Save and use</button>
        </div>
      </div>
    </div>
  `;
}

function renderNodeModal(modal) {
  if (!STATIC_MODE) {
    const status = state.chain?.status;
    return `
      <div class="modal-backdrop" data-action="close-modal">
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="node-modal-title">
          <div class="modal-head">
            <div><p class="eyebrow">rnode choice</p><h2 id="node-modal-title">Server-selected rnode</h2></div>
            <button class="modal-close" data-action="close-modal" aria-label="Close">×</button>
          </div>
          <p class="card-lede">The local Node server chooses its rholo endpoint with <span class="mono-inline">RHOLO_URL</span>. Change it in <span class="mono-inline">.env</span> and restart the server to switch.</p>
          <div class="chain-status-list">
            <div class="chain-status-row"><span>Endpoint</span><span>${esc(state.config?.chain?.url || '—')}</span></div>
            <div class="chain-status-row"><span>Network</span><span>${esc(status?.networkId || '—')}</span></div>
            <div class="chain-status-row"><span>Shard</span><span>${esc(status?.shardId || '—')}</span></div>
            <div class="chain-status-row"><span>Latest block</span><span>${esc(status?.latestBlockNumber ?? '—')}</span></div>
          </div>
          <div class="modal-actions"><button class="btn btn-ghost" data-action="close-modal">Close</button></div>
        </div>
      </div>
    `;
  }

  if (modal.draft) return renderNodeForm(modal.draft);

  const nodes = allNodes(state.customNodes);
  const selected = findNode(modal.nodeId, state.customNodes) || state.node || DEFAULT_NODE;
  const groups = nodeGroups(nodes);
  const active = selected.id === state.node?.id;
  const status = active ? state.chain?.status : null;
  const caps = active ? state.chain?.capabilities : null;
  const readOnly = Boolean(selected.readOnly) || (active && caps && caps.faucet === false);
  const insecure =
    nodeUrl(selected).startsWith('http://') && window.location.protocol === 'https:';
  const optionHtml = [...groups.entries()]
    .map(
      ([group, groupNodes]) => `
        <optgroup label="${esc(group)}">
          ${groupNodes
            .map(
              (node) =>
                `<option value="${esc(node.id)}" ${node.id === selected.id ? 'selected' : ''}>${esc(node.name)} → ${esc(nodeUrl(node))}</option>`,
            )
            .join('')}
        </optgroup>`,
    )
    .join('');

  return `
    <div class="modal-backdrop" data-action="close-modal">
      <div class="modal wide" role="dialog" aria-modal="true" aria-labelledby="node-modal-title">
        <div class="modal-head">
          <div>
            <p class="eyebrow">rnode choice</p>
            <h2 id="node-modal-title">Choose an rnode</h2>
          </div>
          <button class="modal-close" data-action="close-modal" aria-label="Close">×</button>
        </div>
        <p class="card-lede">BYOID reads the DID log and submits anchors through this node. The built-in list mirrors r-wallet; custom nodes stay in this browser.</p>
        <label class="field-label" for="rnode-select">rnode endpoint</label>
        <select id="rnode-select" class="node-select" data-action="select-rnode">
          ${optionHtml}
        </select>
        <div class="node-summary">
          <div class="chain-status-row"><span>URL</span><span class="mono">${esc(nodeUrl(selected))}</span></div>
          <div class="chain-status-row"><span>Group / network</span><span>${esc(selected.group || 'Custom')} · ${esc(status?.networkId || selected.network || 'custom')}</span></div>
          <div class="chain-status-row"><span>Status</span><span>${active ? (status ? `current · verified · block ${esc(status.latestBlockNumber ?? '—')}` : 'current · status unavailable') : 'pending — press Use this node'}</span></div>
          <div class="chain-status-row"><span>Writes / faucet</span><span>${readOnly ? 'read-only or no faucet' : active && caps ? (caps.faucet ? 'writes + faucet' : 'writes, no faucet') : 'checked after connecting'}</span></div>
        </div>
        ${
          insecure
            ? '<div class="node-warning">This page is served over HTTPS, so the browser will block an http:// rnode. Use an https:// URL or run BYOID locally.</div>'
            : ''
        }
        ${
          readOnly
            ? '<div class="node-warning">This node is read-only or does not advertise a faucet. DID anchoring will fail here; verification reads still work.</div>'
            : ''
        }
        ${
          !active && state.wallet
            ? '<div class="node-warning">Your current DID may not exist on this chain. After switching, use “Anchor now” or “New identity” if needed.</div>'
            : ''
        }
        <div class="node-actions">
          <button class="btn btn-ghost btn-sm" data-action="new-rnode">${uiIcon('layers')} Add custom node</button>
          ${
            selected.editable
              ? `<button class="btn btn-ghost btn-sm" data-action="edit-rnode">Edit</button>
                 <button class="btn btn-danger btn-sm" data-action="delete-rnode">Remove</button>`
              : ''
          }
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" data-action="close-modal">Cancel</button>
          <button class="btn btn-primary" data-action="use-rnode">${active ? 'Reconnect' : 'Use this node'}</button>
        </div>
      </div>
    </div>
  `;
}

function renderDemoModal(modal) {
  const provider = providerById(modal.providerId);
  if (!provider) return '';
  const profile = provider.demoProfiles?.find((item) => item.id === modal.profileId) || provider.demoProfiles?.[0];
  return `
    <div class="modal-backdrop" data-action="close-modal">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="demo-modal-title">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Simulated provider consent</p>
            <h2 id="demo-modal-title">Connect ${esc(provider.name)}</h2>
          </div>
          <button class="modal-close" data-action="close-modal" aria-label="Close">×</button>
        </div>
        <div class="demo-callout">
          <strong>Demo mode.</strong> No request is sent to ${esc(provider.name)}. The server signs an attestation with
          <span class="mono-inline">demo: true</span> so the verifier can tell it apart. Add
          <span class="mono-inline">${esc(provider.configure.clientIdEnv)}</span> and
          <span class="mono-inline">${esc(provider.configure.clientSecretEnv)}</span> to <span class="mono-inline">.env</span>
          to use the live OAuth provider.
        </div>
        <p class="card-lede">Choose the demo profile this link should represent. The raw profile stays in your wallet; only a hash goes on rholo.</p>
        ${(provider.demoProfiles || [])
          .map(
            (item) => `
          <label class="profile-option ${item.id === profile?.id ? 'is-selected' : ''}">
            <input type="radio" name="demo-profile" value="${esc(item.id)}" data-action="select-demo-profile" data-provider="${esc(provider.id)}" ${item.id === profile?.id ? 'checked' : ''} />
            ${avatarHtml(item.id, item.label)}
            <span class="profile-option-text"><strong>${esc(item.label)}</strong><span>${esc(item.handle)} · ${esc(item.email)}</span></span>
            ${item.id === profile?.id ? '<span class="badge badge-accent">selected</span>' : ''}
          </label>`,
          )
          .join('')}
        <div class="permissions">
          <h4>BYOID will receive</h4>
          <ul>
            <li>A stable ${esc(provider.name)} subject id (hashed on chain)</li>
            <li>${esc(provider.scopes.join(', '))}</li>
            <li>The profile fields shown above, for your wallet only</li>
          </ul>
        </div>
        <p class="modal-note">The agent signs hashes of the subject, handle, email, name and avatar. A credential can later disclose any subset; the attestation itself never contains the raw values.</p>
        <div class="modal-actions">
          <button class="btn btn-ghost" data-action="close-modal">Cancel</button>
          <button class="btn btn-primary" data-action="authorize-demo" data-provider="${esc(provider.id)}" ${profile ? '' : 'disabled'}>
            Authorize as ${esc(profile?.label || 'demo profile')}
          </button>
        </div>
      </div>
    </div>
  `;
}

function renderIssueModal(modal) {
  const provider = providerById(modal.providerId);
  const link = (state.wallet?.links || []).find((item) => item.provider === modal.providerId);
  if (!provider || !link) return '';
  const fields = modal.fields || DEFAULT_ISSUE_FIELDS;
  const fieldOptions = [
    ['handle', 'Handle', link.profile?.handle || 'none'],
    ['email', 'Email address', link.profile?.email || 'none'],
    ['emailVerified', 'Email verified flag', link.profile?.emailVerified ? 'true' : 'not asserted'],
    ['verifiedAt', 'Verification date', fmtDate(link.linkedAt)],
    ['name', 'Full name', link.profile?.name || 'none'],
  ];
  const included = ['provider', ...fieldOptions.filter(([key]) => fields[key]).map(([key]) => fieldLabel(key))];
  return `
    <div class="modal-backdrop" data-action="close-modal">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="issue-modal-title">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Step 4 · selective disclosure</p>
            <h2 id="issue-modal-title">Issue a ${esc(provider.name)} credential</h2>
          </div>
          <button class="modal-close" data-action="close-modal" aria-label="Close">×</button>
        </div>
        <div class="linked-profile" style="margin-bottom:14px">
          ${avatarHtml(link.subjectHash, link.profile?.name || provider.name, { small: true })}
          <div class="linked-profile-text"><strong>${esc(link.profile?.handle || 'linked account')}</strong><span>${esc(link.profile?.email || link.profile?.name || link.subjectHash)}</span></div>
          <span class="badge ${link.demo ? 'badge-warn' : 'badge-teal'}">${link.demo ? 'demo' : 'verified'}</span>
        </div>
        <p class="card-lede">The credential is signed by your DID key over exactly the fields you include. Anything you leave out is absent from the document — not merely hidden.</p>
        <div class="field-checks">
          ${fieldOptions
            .map(
              ([key, label, value]) => `
            <label class="field-check">
              <input type="checkbox" data-action="toggle-issue-field" data-field="${esc(key)}" ${fields[key] ? 'checked' : ''} />
              <span class="field-check-text"><strong>${esc(label)}</strong><span>${esc(value)}</span></span>
            </label>`,
            )
            .join('')}
        </div>
        <div class="permissions">
          <h4>The verifier will see</h4>
          <ul>${included.map((item) => `<li>${esc(item)}</li>`).join('')}<li>The provider subject hash and the agent attestation (hashes only)</li></ul>
        </div>
        <p class="modal-note">The attestation is what stops a credential from lying: the verifier hashes every included field and checks it against the signed attestation and the link event on rholo. A new credential is a new signature; re-issue to change the disclosure set.</p>
        <div class="modal-actions">
          <button class="btn btn-ghost" data-action="close-modal">Cancel</button>
          <button class="btn btn-primary" data-action="issue-credential" data-provider="${esc(provider.id)}">Sign credential in my browser</button>
        </div>
      </div>
    </div>
  `;
}

function renderPresentModal() {
  const records = (state.wallet?.credentials || []).filter(
    (record) => !record.revokedAt && !record.revokedOnChain,
  );
  const selected = records.filter((record) => state.selectedCredentials.has(record.id));
  return `
    <div class="modal-backdrop" data-action="close-modal">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="present-modal-title">
        <div class="modal-head">
          <div><p class="eyebrow">Selective disclosure</p><h2 id="present-modal-title">Choose what to present</h2></div>
          <button class="modal-close" data-action="close-modal" aria-label="Close">×</button>
        </div>
        <p class="card-lede">Only the credentials you tick go into the presentation. Each is independently signed, so the verifier can check the ones you include without learning about the others.</p>
        <div class="credential-list">
          ${records
            .map((record) => {
              const summary = credentialSummary(record);
              return `
                <label class="credential-card ${state.selectedCredentials.has(record.id) ? 'is-selected' : ''}">
                  <div class="cred-check"><input class="check" type="checkbox" data-action="toggle-present-credential" data-credential-id="${esc(record.id)}" ${state.selectedCredentials.has(record.id) ? 'checked' : ''} /></div>
                  <div class="cred-main">
                    <div class="cred-title"><span class="provider-logo" style="width:26px;height:26px;border-radius:8px">${brandIcon(summary.providerId)}</span><strong>${esc(providerById(summary.providerId)?.name || summary.providerId)}</strong>${record.demo ? '<span class="badge badge-warn">demo</span>' : ''}</div>
                    <div class="cred-fields">${summary.fields.map(([field, value]) => `<span class="field-chip"><strong>${esc(fieldLabel(field))}:</strong> ${esc(value)}</span>`).join('')}${summary.hidden.map((field) => `<span class="field-chip is-hidden">${esc(fieldLabel(field))}: not included</span>`).join('')}</div>
                  </div>
                </label>`;
            })
            .join('')}
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" data-action="close-modal">Cancel</button>
          <button class="btn btn-accent" data-action="confirm-present" ${selected.length ? '' : 'disabled'}>Present ${selected.length || ''} credential${selected.length === 1 ? '' : 's'}</button>
        </div>
      </div>
    </div>
  `;
}

function renderImportModal() {
  return `
    <div class="modal-backdrop" data-action="close-modal">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="import-modal-title">
        <div class="modal-head">
          <div><p class="eyebrow">Wallet backup</p><h2 id="import-modal-title">Export or import</h2></div>
          <button class="modal-close" data-action="close-modal" aria-label="Close">×</button>
        </div>
        <p class="card-lede">The wallet key lives only in this browser. A backup is a JSON file containing the private key — anyone who has it can act as your DID.</p>
        <div class="info-box" style="margin-bottom:14px">
          <h4>What the backup contains</h4>
          <ul><li>The DID and public key</li><li>The private P-256 key</li><li>Signed create/link/revoke events and receipts</li><li>Credentials and linked profile metadata</li></ul>
        </div>
        <div class="card-actions">
          <button class="btn btn-primary" data-action="export-wallet">${uiIcon('download')} Export wallet JSON</button>
          <label class="btn btn-secondary" for="wallet-import-file">${uiIcon('upload')} Import a backup
            <input id="wallet-import-file" type="file" accept="application/json,.json" data-action="import-file" hidden />
          </label>
        </div>
        <p class="modal-note">Importing replaces the wallet currently in this browser. The old wallet is not deleted from the chain; it simply stops being available here.</p>
        <div class="help-section">
          <h3>Danger zone</h3>
          <p>Remove the wallet and key from this browser. The on-chain DID log is permanent; you will need the backup to use it again.</p>
          <button class="btn btn-danger btn-sm" data-action="clear-wallet">${uiIcon('trash')} Remove this wallet from the browser</button>
        </div>
        <div class="modal-actions"><button class="btn btn-ghost" data-action="close-modal">Close</button></div>
      </div>
    </div>
  `;
}

function renderHelpModal(modal) {
  const providerRows = (state.config?.providers || [])
    .map((provider) => {
      const envNames = [
        provider.configure.clientIdEnv,
        provider.configure.clientSecretEnv,
        ...(provider.configure.extraEnv || []),
      ].filter(Boolean);
      return `
      <tr>
        <td>${esc(provider.name)}</td>
        <td><span class="badge ${provider.mode === 'live' ? 'badge-ok' : provider.mode === 'demo' ? 'badge-warn' : 'badge-quiet'}">${esc(provider.mode)}</span></td>
        <td>${envNames.map((name) => `<code>${esc(name)}</code>`).join('<br />')}</td>
        <td><code>${esc(provider.configure.redirectUri)}</code></td>
      </tr>`;
    })
    .join('');
  return `
    <div class="modal-backdrop" data-action="close-modal">
      <div class="modal wide" role="dialog" aria-modal="true" aria-labelledby="help-modal-title">
        <div class="modal-head">
          <div><p class="eyebrow">Self-evident by construction</p><h2 id="help-modal-title">How this POC works</h2></div>
          <button class="modal-close" data-action="close-modal" aria-label="Close">×</button>
        </div>
        <p class="help-issue-shortcut"><a href="https://github.com/rhovision-org/BYOID/issues/new" target="_blank" rel="noopener">${uiIcon('external')} Found a problem? Add an issue</a></p>
        <div class="help-section">
          <h3>The four moves</h3>
          <ol>
            <li><strong>Create.</strong> A P-256 keypair is generated in your browser. The DID is a hash of its public key, so it is self-certifying. The create event is signed by that key.</li>
            <li><strong>Link.</strong> Google, GitHub, Facebook or Apple proves control of an account. The BYOID agent signs an attestation containing only hashes. Your wallet signs a link event that commits to the attestation hash.</li>
            <li><strong>Anchor.</strong> Each signed event is written to a public name on the rholo playground: <code>byoid:did:&lt;method-specific-id&gt;</code>. The server pays phlo; it cannot sign as you.</li>
            <li><strong>Prove.</strong> A credential is signed in your browser over only the fields you include. The verifier resolves your DID from rholo, checks the hash-linked event log, each attestation and the revocation list.</li>
          </ol>
        </div>
        <div class="help-section">
          <h3>Who can do what</h3>
          <ul>
            <li><strong>Wallet key</strong> — in IndexedDB, never sent. Signs events, credentials and presentations.</li>
            <li><strong>Agent key</strong> — server-side. Signs hash-only link attestations; its public key is published on rholo.</li>
            <li><strong>Deploy key</strong> — server-side, generated in <code>data/deployer-key.json</code>. Pays phlo. It cannot forge a DID event.</li>
          </ul>
        </div>
        <div class="help-section" id="help-oauth">
          <h3>Enable real Google / GitHub / Facebook / Apple OAuth</h3>
          <p>Out of the box each provider runs in <strong>demo mode</strong>, a clearly-labelled local simulation, so the POC works with no credentials. Live OAuth requires the Node server because it must keep client secrets and sign the link attestation; the GitHub Pages build has no server and therefore stays in demo mode.</p>
          <p>Create the provider apps, register the exact redirect URI from the table below, add the values to <code>.env</code>, and restart:</p>
          <pre class="code-block light">PUBLIC_URL=http://localhost:3000

# Google (OIDC)
GOOGLE_CLIENT_ID=…
GOOGLE_CLIENT_SECRET=…

# GitHub (OAuth 2.0)
GITHUB_CLIENT_ID=…
GITHUB_CLIENT_SECRET=…

# Facebook (OAuth 2.0)
FACEBOOK_CLIENT_ID=…
FACEBOOK_CLIENT_SECRET=…

# Apple (OIDC / Sign in with Apple)
APPLE_CLIENT_ID=…
APPLE_TEAM_ID=…
APPLE_KEY_ID=…
APPLE_PRIVATE_KEY_PATH=./AuthKey_XXXXXXXXXX.p8
# or supply a pre-generated APPLE_CLIENT_SECRET JWT instead of the key pair</pre>
          <p style="margin-top:10px">Register these exact redirect URIs:</p>
          <div style="overflow:auto"><table class="setup-table"><thead><tr><th>Provider</th><th>Mode</th><th>Environment</th><th>Redirect URI</th></tr></thead><tbody>${providerRows}</tbody></table></div>
          <p style="margin-top:10px">Apple uses a Services ID as the client id, a Team ID, a Key ID, and the <code>.p8</code> private key. BYOID builds the short-lived Apple client-secret JWT for you. Never put these values in the static GitHub Pages build.</p>
        </div>
        <div class="help-section">
          <h3>Run it yourself</h3>
          <pre class="code-block light">npm install
npm start
# open http://localhost:3000

# point at another rholo node (default: the public playground)
RHOLO_URL=https://playground.rhobot.net npm start
# run the UI without chain writes
CHAIN_WRITES=false npm start</pre>
        </div>
        <div class="help-section" id="help-rev-proofs">
          <h3>Keybase-style proofs by REV address</h3>
          <p>The Chain tab can publish a proof card that binds a secp256k1 REV address to your DID. The card is signed by both keys, lists the provider handles you choose to disclose, and is anchored at <code>byoid:rev:&lt;address&gt;</code>. A Rholang registry contract at <code>byoid:rev:registry</code> indexes the latest card. Lookups verify the signatures and every provider attestation before displaying a result.</p>
          <a class="btn btn-ghost btn-sm" href="https://github.com/rhovision-org/BYOID/blob/main/docs/rev-proofs.md" target="_blank" rel="noopener">${uiIcon('external')} Proof-card specification</a>
        </div>
        <div class="help-section" id="help-issues">
          <h3>Report a bug or request a feature</h3>
          <p>Issues and design discussions live in the community repository. If something is broken, unclear, or missing, open an issue with the steps you followed and which rnode you used.</p>
          <a class="btn btn-secondary" href="https://github.com/rhovision-org/BYOID/issues/new" target="_blank" rel="noopener">${uiIcon('external')} Add an issue</a>
        </div>
        <div class="help-section">
          <h3>Limits worth naming</h3>
          <ul>
            <li>The rholo playground is a public dev chain and may reset. Do not use test data for anything real.</li>
            <li>A public tuple-space name is a bulletin board: anyone can write to it. Integrity comes from signatures and the hash-linked chain, and the resolver ignores invalid events, gaps and forks. A production DID method would use an unforgeable-name registry with a controller capability.</li>
            <li>Demo providers are simulations by design, not a bypass for real OAuth. Google, GitHub, Facebook and Apple demo attestations carry <code>demo: true</code>. Live OAuth requires the Node server.</li>
            <li>REV proof cards are public by design: the handles you publish become visible. The card proves control of the REV key and the DID, and every provider attestation is checked against an anchored link event.</li>
            <li>The Rholang registry contract at <code>byoid:rev:registry</code> indexes the latest card per address. The app also mirrors cards at <code>byoid:rev:&lt;address&gt;</code>, so a lookup is a read and does not require a deploy.</li>
            <li>This is a POC, not an audited identity system. The wallet key is extractable so you can back it up; treat the browser as sensitive.</li>
          </ul>
        </div>
        <div class="modal-actions"><button class="btn btn-primary" data-action="close-modal">Got it</button></div>
      </div>
    </div>
  `;
}

function renderModal() {
  const root = $('#modal-root');
  if (!root) return;
  const modal = state.modal;
  if (!modal) {
    root.innerHTML = '';
    return;
  }
  let html = '';
  if (modal.type === 'demo') html = renderDemoModal(modal);
  else if (modal.type === 'node') html = renderNodeModal(modal);
  else if (modal.type === 'issue') html = renderIssueModal(modal);
  else if (modal.type === 'present') html = renderPresentModal();
  else if (modal.type === 'import') html = renderImportModal();
  else if (modal.type === 'help') html = renderHelpModal(modal);
  root.innerHTML = html;
}

// ── render all ──────────────────────────────────────────────────────────────

function renderAll() {
  renderHeader();
  renderStepper();
  renderTabs();
  renderWallet();
  renderVerify();
  renderChain();
  renderModal();
  renderProgress();
}

// ── initial load / URL hints ────────────────────────────────────────────────

async function loadConfig() {
  const [config, chain, agent] = await Promise.allSettled([
    api('/api/config'),
    api('/api/chain/status'),
    api('/api/agent'),
  ]);
  if (config.status === 'fulfilled') state.config = config.value;
  if (chain.status === 'fulfilled') state.chain = chain.value;
  if (agent.status === 'fulfilled') state.agent = agent.value;
  if (config.status === 'rejected') throw config.reason;
}

async function restoreWallet() {
  const wallet = loadWalletMeta();
  if (!wallet) return;
  state.wallet = ensureWalletShape(wallet);
  try {
    const key = await idbGet(PRIVATE_KEY_ID);
    if (!key) {
      state.keyError = 'The key for this wallet is not in this browser.';
      return;
    }
    const challenge = utf8('byoid-wallet-load-check');
    const signature = await signEs256(key, challenge);
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      publicJwkOf(state.wallet.publicJwk),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signature,
      challenge,
    );
    if (!valid) {
      state.keyError = 'The stored key does not match this wallet.';
      return;
    }
    state.privateKey = key;
    state.keyError = null;
  } catch (error) {
    state.keyError = error.message;
  }
}

async function processUrlHints() {
  const url = new URL(window.location.href);
  const oauthError = url.searchParams.get('oauth_error');
  const linked = url.searchParams.get('linked');
  const connect = url.searchParams.get('connect');
  const hash = url.hash.slice(1);

  if (oauthError) {
    toast({ kind: 'bad', title: 'Provider sign-in did not complete', message: oauthError });
  }
  if (connect) {
    if (state.wallet) {
      connectProvider(connect);
    } else {
      toast({ kind: 'warn', title: 'Create your identity first', message: 'Then connect the provider.' });
    }
  }
  if (linked || (state.wallet && state.config)) {
    try {
      const session = await api('/api/session');
      if (session.pendingLink) {
        if (!state.wallet) {
          await api('/api/session/consume-link', { method: 'POST' });
          toast({
            kind: 'bad',
            title: 'A provider sign-in is waiting, but this browser has no wallet',
            message: 'Create or import the wallet it was started from, then connect again.',
          });
        } else if (session.pendingLink.did !== state.wallet.did) {
          await api('/api/session/consume-link', { method: 'POST' });
          toast({
            kind: 'bad',
            title: 'That sign-in is bound to a different DID',
            message: 'Start the provider connection from this wallet.',
          });
        } else {
          const pending = session.pendingLink;
          await api('/api/session/consume-link', { method: 'POST' });
          await withBusy('Completing the provider link…', async () => {
            try {
              await completeLink(pending);
            } catch (error) {
              toast({ kind: 'bad', title: 'Could not complete the link', message: error.message });
            }
          });
        }
      } else if (linked) {
        toast({ kind: 'warn', title: 'No pending sign-in found', message: 'Start the provider connection from your wallet.' });
      }
    } catch {
      // The session endpoint is best-effort; the wallet still works without it.
    }
  }

  if (hash.startsWith('present=')) {
    try {
      const json = new TextDecoder().decode(unb64url(hash.slice('present='.length)));
      const presentation = JSON.parse(json);
      setTab('verify');
      await runVerify(presentation);
    } catch {
      toast({ kind: 'bad', title: 'That share link is not a valid presentation' });
    }
  } else if (hash === 'chain') {
    setTab('chain');
  }

  if (oauthError || linked || connect) {
    window.history.replaceState({}, '', `${url.pathname}${url.hash.startsWith('#present=') ? url.hash : ''}`);
  }
}

// ── delegated events ────────────────────────────────────────────────────────

document.addEventListener('click', async (event) => {
  const target = event.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;

  if (target.tagName === 'A') event.preventDefault();

  try {
    switch (action) {
      case 'tab':
        setTab(target.dataset.tab || 'wallet');
        if (target.dataset.tab === 'wallet') scrollToId('wallet-root');
        break;
      case 'hero-start':
        setTab('wallet');
        scrollToId('wallet-root');
        if (!state.wallet) {
          toast({ kind: 'info', title: 'Start with a key', message: 'Create your identity, then connect accounts.' });
        }
        break;
      case 'create-identity':
        await createIdentity();
        break;
      case 'new-identity':
        await startOverWithNewIdentity();
        break;
      case 'retry-create':
        await retryCreateAnchor();
        break;
      case 'refresh-did':
        await withBusy('Reading the DID log from rholo…', async () => {
          await refreshResolution({ force: true });
          renderAll();
          toast({ kind: 'ok', title: 'DID log refreshed' });
        });
        break;
      case 'copy-wallet-did':
        if (state.wallet) await copyText(state.wallet.did, 'DID copied');
        break;
      case 'export-wallet':
        await exportWallet();
        break;
      case 'open-import':
        state.modal = { type: 'import' };
        renderModal();
        break;
      case 'clear-wallet':
        await clearWallet();
        break;
      case 'connect-provider':
        connectProvider(target.dataset.provider);
        break;
      case 'retry-link':
        await retryLinkAnchor(target.dataset.provider);
        break;
      case 'select-demo-profile':
        if (state.modal?.type === 'demo') {
          state.modal.profileId = target.value;
          renderModal();
        }
        break;
      case 'authorize-demo':
        await authorizeDemo();
        break;
      case 'issue-credential-open':
        if (!state.wallet) break;
        if (!(state.wallet.links || []).length) {
          toast({ kind: 'warn', title: 'Connect an account first', message: 'A credential needs an anchored link.' });
          break;
        }
        state.modal = {
          type: 'issue',
          providerId: target.dataset.provider || state.wallet.links[0].provider,
          fields: { ...DEFAULT_ISSUE_FIELDS },
        };
        renderModal();
        break;
      case 'toggle-issue-field':
        if (state.modal?.type === 'issue') {
          state.modal.fields[target.dataset.field] = target.checked;
          renderModal();
        }
        break;
      case 'issue-credential':
        await withBusy('Signing the credential in your browser…', issueCredentialFromModal);
        break;
      case 'toggle-credential':
        if (target.checked) state.selectedCredentials.add(target.dataset.credentialId);
        else state.selectedCredentials.delete(target.dataset.credentialId);
        renderWallet();
        break;
      case 'toggle-present-credential':
        if (target.checked) state.selectedCredentials.add(target.dataset.credentialId);
        else state.selectedCredentials.delete(target.dataset.credentialId);
        renderModal();
        break;
      case 'present-selected':
        await presentSelected();
        break;
      case 'present-from-wallet':
        if (!state.wallet?.credentials?.length) {
          toast({ kind: 'warn', title: 'No credentials in this wallet', message: 'Issue one from a linked account first.' });
          setTab('wallet');
          break;
        }
        if (!state.selectedCredentials.size) {
          for (const record of state.wallet.credentials) {
            if (!record.revokedAt && !record.revokedOnChain) state.selectedCredentials.add(record.id);
          }
        }
        state.modal = { type: 'present' };
        renderModal();
        break;
      case 'confirm-present': {
        const records = (state.wallet?.credentials || []).filter(
          (record) => state.selectedCredentials.has(record.id) && !record.revokedAt && !record.revokedOnChain,
        );
        await withBusy('Signing the presentation in your browser…', () => presentCredentials(records));
        break;
      }
      case 'copy-credential': {
        const record = (state.wallet?.credentials || []).find((item) => item.id === target.dataset.credentialId);
        if (record) await copyText(JSON.stringify(record.credential, null, 2), 'Credential JSON copied');
        break;
      }
      case 'revoke-credential':
        await revokeCredential(target.dataset.credentialId);
        break;
      case 'verify-paste':
        await verifyFromTextarea();
        break;
      case 'clear-presentation':
        state.verifier = { status: 'idle', presentation: null, result: null, error: null };
        const input = $('#presentation-input');
        if (input) input.value = '';
        renderVerify();
        break;
      case 'copy-proof':
        if (state.verifier.presentation) {
          await copyText(JSON.stringify(state.verifier.presentation, null, 2), 'Presentation copied');
        } else if (state.verifier.credential) {
          await copyText(JSON.stringify(state.verifier.credential, null, 2), 'Credential copied');
        }
        break;
      case 'download-proof':
        if (state.verifier.presentation) {
          downloadJson(`byoid-presentation-${shortId(state.verifier.presentation.id || '', 12, 6)}.json`, state.verifier.presentation);
        } else if (state.verifier.credential) {
          downloadJson(`byoid-credential-${shortId(state.verifier.credential.id || '', 12, 6)}.json`, state.verifier.credential);
        }
        break;
      case 'copy-share-link': {
        if (!state.verifier.presentation) break;
        const encoded = b64url(utf8(JSON.stringify(state.verifier.presentation)));
        await copyText(
          `${window.location.origin}${window.location.pathname}#present=${encoded}`,
          'Share link copied',
        );
        break;
      }
      case 'refresh-chain':
        await withBusy('Refreshing chain evidence…', async () => {
          await Promise.allSettled([
            api('/api/chain/status').then((value) => { state.chain = value; }),
            api('/api/agent').then((value) => { state.agent = value; }),
          ]);
          if (state.wallet) await refreshResolution({ force: true, quiet: true });
          renderAll();
          toast({ kind: 'ok', title: 'Chain evidence refreshed' });
        });
        break;
      case 'anchor-agent':
        await withBusy('Publishing the agent key on rholo…', async () => {
          try {
            const response = await api('/api/agent/anchor', { method: 'POST' });
            state.agent = response.agent;
            renderAll();
            toast({ kind: 'ok', title: 'Agent key published', message: response.anchor?.blockNumber ? `Block ${response.anchor.blockNumber}` : 'Key anchor is on chain.' });
          } catch (error) {
            toast({ kind: 'bad', title: 'Agent key publish failed', message: error.message });
          }
        });
        break;
      case 'lookup-proofs':
        await lookupProofsFromInput();
        break;
      case 'use-my-rev-address':
        await ensureRevProofKey();
        state.proofQuery = state.revKey?.address || '';
        if ($('#proof-query')) $('#proof-query').value = state.proofQuery;
        await lookupProofsFromInput();
        break;
      case 'copy-rev-address':
        if (state.revKey) await copyText(state.revKey.address, 'REV address copied');
        break;
      case 'publish-rev-proofs':
        await publishRevProofs();
        break;
      case 'open-node-picker':
        state.modal = {
          type: 'node',
          nodeId: state.node?.id || DEFAULT_NODE.id,
          draft: null,
        };
        renderModal();
        break;
      case 'use-rnode':
        await useSelectedNode();
        break;
      case 'new-rnode':
        state.modal = {
          type: 'node',
          nodeId: state.node?.id || DEFAULT_NODE.id,
          draft: newCustomNode(),
        };
        renderModal();
        break;
      case 'edit-rnode': {
        const node = selectedNodeFromModal();
        if (node?.editable) {
          state.modal.draft = { ...node };
          renderModal();
        }
        break;
      }
      case 'delete-rnode':
        await removeSelectedCustomNode();
        break;
      case 'save-rnode':
        await saveNodeDraft();
        break;
      case 'cancel-rnode-edit':
        if (state.modal?.type === 'node') {
          state.modal.draft = null;
          renderModal();
        }
        break;
      case 'open-help':
        state.modal = { type: 'help', section: target.dataset.section || null };
        renderModal();
        break;
      case 'close-modal':
        if (event.target === target || target.classList.contains('modal-close') || target.classList.contains('btn')) {
          state.modal = null;
          renderModal();
        }
        break;
      case 'close-progress':
        state.progress = null;
        renderProgress();
        break;
      case 'dismiss-toast': {
        const toastElement = target.closest('.toast');
        if (toastElement) toastElement.remove();
        break;
      }
      default:
        break;
    }
  } catch (error) {
    console.error(error);
    toast({ kind: 'bad', title: 'Something went wrong', message: error.message });
  }
});

document.addEventListener('change', async (event) => {
  const target = event.target.closest('[data-action]');
  if (!target) return;
  if (target.dataset.action === 'import-file') {
    const file = target.files?.[0];
    if (file) await importWalletFile(file);
    target.value = '';
  }
  if (target.dataset.action === 'select-demo-profile' && state.modal?.type === 'demo') {
    state.modal.profileId = target.value;
    renderModal();
  }
  if (target.dataset.action === 'toggle-issue-field' && state.modal?.type === 'issue') {
    state.modal.fields[target.dataset.field] = target.checked;
    renderModal();
  }
  if (target.dataset.action === 'toggle-present-credential') {
    if (target.checked) state.selectedCredentials.add(target.dataset.credentialId);
    else state.selectedCredentials.delete(target.dataset.credentialId);
    renderModal();
  }
  if (target.dataset.action === 'select-rnode' && state.modal?.type === 'node') {
    state.modal.nodeId = target.value;
    state.modal.draft = null;
    renderModal();
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && event.target?.id === 'proof-query') {
    event.preventDefault();
    lookupProofsFromInput();
    return;
  }
  if (event.key === 'Escape' && state.modal) {
    state.modal = null;
    renderModal();
  }
});

// Drag and drop a presentation file onto the verify card.
function wireDropZone() {
  const card = document.querySelector('.verify-input-card');
  const hint = $('#drop-hint');
  if (!card) return;
  const over = (event) => {
    event.preventDefault();
    hint?.classList.add('is-dragging');
  };
  const leave = () => hint?.classList.remove('is-dragging');
  card.addEventListener('dragover', over);
  card.addEventListener('dragleave', leave);
  card.addEventListener('drop', async (event) => {
    event.preventDefault();
    leave();
    const file = event.dataTransfer?.files?.[0];
    if (!file) return;
    const text = await file.text();
    const input = $('#presentation-input');
    if (input) input.value = text;
    await verifyFromTextarea();
  });
}

// ── boot ────────────────────────────────────────────────────────────────────

async function boot() {
  if (STATIC_MODE) {
    const banner = $('#static-banner');
    if (banner) banner.hidden = false;
    const configLink = $('#api-config-link');
    if (configLink) {
      configLink.href = 'https://github.com/rhovision-org/BYOID#readme';
      configLink.textContent = 'Project README';
    }
    document.documentElement.dataset.static = 'true';
  }
  try {
    await loadConfig();
    await restoreWallet();
    if (state.wallet) {
      await refreshResolution({ force: false, quiet: true });
      state.wallet.fingerprint ||= `sha256:${await sha256B64url(canonicalize(state.wallet.publicJwk))}`;
      await ensureRevProofKey().catch(() => {});
      saveWallet();
    }
    renderAll();
    wireDropZone();
    if (state.tab !== 'wallet' && state.tab !== 'verify' && state.tab !== 'chain') state.tab = 'wallet';
    renderTabs();
    await processUrlHints();
    renderAll();
  } catch (error) {
    console.error(error);
    const root = $('#wallet-root');
    if (root) {
      root.innerHTML = `
        <div class="card">
          <div class="verdict bad"><div class="verdict-icon">!</div><div><h3>The app could not start</h3><p>${esc(error.message)}</p></div></div>
          <p class="small muted">${STATIC_MODE ? 'The live GitHub Pages build could not initialise. Check that the rholo playground is reachable and reload.' : 'Check that the BYOID server is running and that <span class="mono-inline">RHOLO_URL</span> points at a reachable rholo node.'}</p>
          <button class="btn btn-secondary btn-sm" onclick="location.reload()">Reload</button>
        </div>`;
    }
  }
}

boot();
