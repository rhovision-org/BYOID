// Browser port of the rholo HTTP client used by the GitHub Pages build.
//
// It talks directly to the public rholo playground (CORS is open), signs
// deploys with a browser-generated secp256k1 key, asks the dev faucet for REV,
// and reads the DID event log back from the tuple space. The deployer key is
// only for paying phlo on the playground; the identity key remains the P-256
// key managed by the wallet.

import { bs58, blake2b, keccak_256, secp256k1 } from './vendor/rholo-crypto.js';
import { anchorName, b64url, reduceEvents, sha256B64url, unb64url } from './shared.js';

const DEPLOY_ID_RE = /([0-9a-f]{100,300})/i;
const ANCHOR_NAME_RE = /^[A-Za-z0-9:._-]{1,200}$/;
const ANCHOR_VALUE_RE = /^[A-Za-z0-9_-]{1,20000}$/;
const DEPLOYER_KEY = 'byoid.rholo.deployer.v1';
const FUNDED_KEY = 'byoid.rholo.funded.v1';
const FUNDED_TTL_MS = 10 * 60 * 1000;

const utf8 = (value) => new TextEncoder().encode(value);
const hex = (bytes) =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
const unhex = (value) => {
  const text = String(value);
  if (text.length % 2) throw new Error('hex value must have an even length');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
};

export class RholoWebError extends Error {
  constructor(message, { code = 'rholo-error', status = null, body = '', retryable = false } = {}) {
    super(message);
    this.name = 'RholoWebError';
    this.code = code;
    this.status = status;
    this.body = body;
    this.retryable = retryable;
  }
}

function encodeVarint(value) {
  let n = BigInt(value);
  if (n < 0n) throw new Error('negative varints are not supported');
  const out = [];
  while (n >= 0x80n) {
    out.push(Number((n & 0x7fn) | 0x80n));
    n >>= 7n;
  }
  out.push(Number(n));
  return Uint8Array.from(out);
}

function tag(fieldNumber, wireType) {
  return encodeVarint((BigInt(fieldNumber) << 3n) | BigInt(wireType));
}

function bytesField(fieldNumber, bytes) {
  const payload = typeof bytes === 'string' ? utf8(bytes) : bytes;
  const tagBytes = tag(fieldNumber, 2);
  const lengthBytes = encodeVarint(payload.length);
  const out = new Uint8Array(tagBytes.length + lengthBytes.length + payload.length);
  out.set(tagBytes, 0);
  out.set(lengthBytes, tagBytes.length);
  out.set(payload, tagBytes.length + lengthBytes.length);
  return out;
}

function varintField(fieldNumber, value) {
  const tagBytes = tag(fieldNumber, 0);
  const valueBytes = encodeVarint(value);
  const out = new Uint8Array(tagBytes.length + valueBytes.length);
  out.set(tagBytes, 0);
  out.set(valueBytes, tagBytes.length);
  return out;
}

function concat(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function encodeDeployData(data) {
  const parts = [
    bytesField(2, data.term),
    varintField(3, data.timestamp),
    varintField(7, data.phloPrice),
    varintField(8, data.phloLimit),
    varintField(10, data.validAfterBlockNumber),
    bytesField(11, data.shardId),
  ];
  if (Array.isArray(data.attachments) && data.attachments.length) {
    for (const attachment of data.attachments) parts.push(bytesField(12, attachment));
  }
  return concat(parts);
}

export function signDeployData(data, privateKeyHex) {
  const serialized = encodeDeployData(data);
  const digest = blake2b(serialized, { dkLen: 32 });
  const signature = secp256k1.sign(digest, unhex(privateKeyHex));
  return {
    serializedHex: hex(serialized),
    hashHex: hex(digest),
    signatureHex: signature.toDERHex(),
  };
}

export function revAddressFromPublicKey(publicKeyBytes) {
  const pub = Uint8Array.from(publicKeyBytes);
  if (pub.length !== 65 || pub[0] !== 0x04) {
    throw new Error('REV addresses require a 65-byte uncompressed secp256k1 public key');
  }
  const ethAddress = keccak_256(pub.slice(1)).slice(-20);
  const keyHash = keccak_256(ethAddress);
  const payload = new Uint8Array(4 + keyHash.length);
  payload.set([0, 0, 0, 0], 0);
  payload.set(keyHash, 4);
  const checksum = blake2b(payload, { dkLen: 32 }).slice(0, 4);
  const full = new Uint8Array(payload.length + checksum.length);
  full.set(payload, 0);
  full.set(checksum, payload.length);
  return bs58.encode(full);
}

export function deployerFromPrivateKey(privateKeyHex) {
  const privateKey = unhex(privateKeyHex);
  if (privateKey.length !== 32 || !secp256k1.utils.isValidPrivateKey(privateKey)) {
    throw new Error('invalid secp256k1 private key');
  }
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return {
    privateKeyHex: hex(privateKey),
    publicKeyHex: hex(publicKey),
    address: revAddressFromPublicKey(publicKey),
  };
}

export function generateDeployer() {
  return deployerFromPrivateKey(hex(secp256k1.utils.randomPrivateKey()));
}

function loadStoredDeployer() {
  try {
    const raw = localStorage.getItem(DEPLOYER_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed?.privateKeyHex) return null;
    const deployer = deployerFromPrivateKey(parsed.privateKeyHex);
    return { ...deployer, createdAt: parsed.createdAt || null };
  } catch {
    return null;
  }
}

function storeDeployer(deployer) {
  const value = {
    privateKeyHex: deployer.privateKeyHex,
    publicKeyHex: deployer.publicKeyHex,
    address: deployer.address,
    createdAt: deployer.createdAt || new Date().toISOString(),
  };
  try {
    localStorage.setItem(DEPLOYER_KEY, JSON.stringify(value));
  } catch {
    // Storage can be unavailable; the deployer still works for this page life.
  }
  return value;
}

function loadFunded(address) {
  try {
    const record = JSON.parse(localStorage.getItem(FUNDED_KEY) || 'null');
    if (!record || record.address !== address) return false;
    const age = Date.now() - Date.parse(record.at || 0);
    return Number.isFinite(age) && age >= 0 && age < FUNDED_TTL_MS;
  } catch {
    return false;
  }
}

function storeFunded(address) {
  try {
    localStorage.setItem(FUNDED_KEY, JSON.stringify({ address, at: new Date().toISOString() }));
  } catch {
    // Best effort only.
  }
}

export function loadOrCreateDeployer() {
  const existing = loadStoredDeployer();
  if (existing) return existing;
  return storeDeployer({ ...generateDeployer(), createdAt: new Date().toISOString() });
}

export function makeAnchorTerm(name, value) {
  if (!ANCHOR_NAME_RE.test(name)) throw new Error('invalid anchor name');
  if (!ANCHOR_VALUE_RE.test(value)) throw new Error('invalid anchor value');
  return `@"${name}"!(${JSON.stringify(value)})`;
}

export function parseDeployStatus(document) {
  if (!document || typeof document !== 'object') return { state: 'unknown' };
  const success = document.ProcessedWithSuccess || document.processedWithSuccess;
  if (success) {
    return { state: 'success', result: success.deployResult || [], block: success.block || null };
  }
  const failure = document.ProcessedWithError || document.processedWithError;
  if (failure) {
    return {
      state: 'error',
      error: failure.deployError || failure.deploy_error || 'deploy failed',
      block: failure.block || null,
    };
  }
  const pending = document.NotProcessed || document.notProcessed;
  if (pending) return { state: 'pending', status: pending.status || 'not processed' };
  return { state: 'unknown', document };
}

function parseDeployResponse(text) {
  let value = String(text ?? '').trim();
  if (value.startsWith('"')) {
    try {
      value = JSON.parse(value);
    } catch {
      // Keep the raw text for the error below.
    }
  }
  const match = value.match(DEPLOY_ID_RE);
  if (match && /success/i.test(value)) return match[1];
  if (/^[0-9a-f]{100,300}$/i.test(value)) return value;
  throw new RholoWebError(`rholo rejected the deploy: ${value.slice(0, 500)}`, {
    code: 'deploy-rejected',
    body: value,
  });
}

export function decodeDataValues(exprs) {
  const values = [];
  for (const expr of Array.isArray(exprs) ? exprs : []) {
    if (expr?.ExprString?.data !== undefined) {
      values.push(String(expr.ExprString.data));
    } else if (expr?.ExprBytes?.data !== undefined) {
      try {
        const bytes = unhex(expr.ExprBytes.data);
        values.push(new TextDecoder().decode(bytes));
      } catch {
        // Ignore payloads that are not UTF-8 text.
      }
    }
  }
  return values;
}

export class RholoWebClient {
  constructor({
    url = 'https://playground.rhobot.net',
    shardId = null,
    faucet = true,
    timeoutMs = 25000,
    deployWaitMs = 45000,
    phloLimit = 1_000_000,
    phloPrice = 1,
    fetchImpl = (input, init) => fetch(input, init),
    logger = console,
  } = {}) {
    this.url = String(url).replace(/\/+$/, '');
    this.shardId = shardId;
    this.faucetEnabled = faucet;
    this.timeoutMs = timeoutMs;
    this.deployWaitMs = deployWaitMs;
    this.phloLimit = phloLimit;
    this.phloPrice = phloPrice;
    this.fetchImpl = fetchImpl;
    this.logger = logger;
    this.deployer = loadOrCreateDeployer();
    this._funded = loadFunded(this.deployer.address) ? Promise.resolve() : null;
    this._queue = Promise.resolve();
    this._network = null;
    this._networkAt = 0;
  }

  async _request(path, { method = 'GET', body, timeoutMs = this.timeoutMs } = {}) {
    const url = `${this.url}${path}`;
    const init = {
      method,
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
    };
    if (body !== undefined) {
      init.headers['content-type'] = 'application/json';
      init.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    let response;
    try {
      response = await this.fetchImpl(url, init);
    } catch (error) {
      throw new RholoWebError(`cannot reach rholo at ${this.url}: ${error.message}`, {
        code: 'network',
        retryable: true,
      });
    }
    const text = await response.text();
    if (!response.ok) {
      throw new RholoWebError(
        `rholo ${method} ${path} returned HTTP ${response.status}: ${text.slice(0, 400)}`,
        {
          code: 'http',
          status: response.status,
          body: text,
          retryable: response.status >= 500 || response.status === 429,
        },
      );
    }
    return text;
  }

  async _json(path, options) {
    const text = await this._request(path, options);
    try {
      return text ? JSON.parse(text) : null;
    } catch {
      throw new RholoWebError(`rholo ${path} returned non-JSON: ${text.slice(0, 300)}`, {
        code: 'bad-json',
        body: text,
      });
    }
  }

  getStatus() {
    return this._json('/api/v1/status');
  }

  getCapabilities() {
    return this._json('/api/v1/capabilities');
  }

  async network() {
    if (this._network && Date.now() - this._networkAt < 1500) return this._network;
    const status = await this.getStatus();
    this._network = {
      networkId: status.networkId || null,
      shardId: this.shardId || status.shardId || '/root',
      latestBlockNumber: Number(status.latestBlockNumber || 0),
      autopropose: Boolean(status.autopropose),
      proposeOnDeploy: Boolean(status.proposeOnDeploy),
      devMode: Boolean(status.devMode),
    };
    this._networkAt = Date.now();
    return this._network;
  }

  async latestBlock() {
    try {
      const blocks = await this._json('/api/v1/blocks');
      if (Array.isArray(blocks) && blocks.length) return blocks[0];
    } catch {
      // Fall back to the finalized block below.
    }
    const finalized = await this._json('/api/last-finalized-block');
    return finalized?.blockInfo || null;
  }

  getBlock(hash) {
    if (!/^[0-9a-f]{64}$/i.test(String(hash))) throw new Error('invalid block hash');
    return this._json(`/api/v1/block/${hash}`);
  }

  getDeployStatus(deployId) {
    if (!/^[0-9a-f]{100,300}$/i.test(String(deployId))) throw new Error('invalid deploy id');
    return this._json(`/api/v1/deploy-status/${deployId}`);
  }

  async getDataAtName(name, blockHash) {
    if (!/^[0-9a-f]{64}$/i.test(String(blockHash))) {
      throw new Error('data-at-name requires a block hash');
    }
    const response = await this._json('/api/v1/data-at-name-by-block-hash', {
      method: 'POST',
      body: {
        name: { ExprString: { data: name } },
        blockHash,
        usePreStateHash: false,
      },
    });
    return {
      values: decodeDataValues(response?.expr),
      block: response?.block || null,
      raw: response,
    };
  }

  async readName(name) {
    const block = await this.latestBlock();
    if (!block?.blockHash) {
      throw new RholoWebError('rholo did not return a latest block', { code: 'no-block' });
    }
    return this.getDataAtName(name, block.blockHash);
  }

  faucet(address) {
    return this._json('/api/v1/faucet', { method: 'POST', body: { address } });
  }

  _enqueue(fn) {
    const run = this._queue.then(fn, fn);
    this._queue = run.catch(() => {});
    return run;
  }

  async _ensureFunded() {
    if (!this.faucetEnabled) return;
    if (!this._funded) {
      this._funded = (async () => {
        let response;
        try {
          response = await this.faucet(this.deployer.address);
        } catch (error) {
          if (/previous drip|finality|already/i.test(`${error.message} ${error.body || ''}`)) {
            storeFunded(this.deployer.address);
            this.logger.warn?.('[rholo] faucet already has a drip in flight; assuming funded');
            return;
          }
          // The faucet is best-effort. Try the deploy anyway; if phlo is really
          // missing, submitDeploy clears this cache and retries the faucet.
          this.logger.warn?.(`[rholo] faucet request failed: ${error.message}; trying deploy`);
          return;
        }
        if (!response?.deployId) {
          throw new RholoWebError('the rholo faucet did not return a deploy id', {
            code: 'faucet-failed',
            body: JSON.stringify(response),
          });
        }
        if (response.status === 'failed') {
          throw new RholoWebError(`the rholo faucet failed: ${response.deployError || 'unknown'}`, {
            code: 'faucet-failed',
          });
        }
        const result = await this.waitForDeploy(response.deployId, { timeoutMs: 60000 });
        if (result.state !== 'success') {
          throw new RholoWebError(
            `the rholo faucet drip did not execute: ${result.error || result.state}`,
            { code: 'faucet-failed' },
          );
        }
        storeFunded(this.deployer.address);
        this.logger.info?.(
          `[rholo] faucet funded ${this.deployer.address} (deploy ${response.deployId.slice(0, 16)}…)`,
        );
      })();
      this._funded.catch(() => {
        this._funded = null;
      });
    }
    return this._funded;
  }

  async submitDeploy(term) {
    return this._enqueue(async () => {
      await this._ensureFunded();
      for (let attempt = 0; attempt < 2; attempt++) {
        const network = await this.network();
        const data = {
          term,
          timestamp: Date.now(),
          phloPrice: this.phloPrice,
          phloLimit: this.phloLimit,
          validAfterBlockNumber: Math.max(0, network.latestBlockNumber - 1),
          shardId: network.shardId,
        };
        const signed = signDeployData(data, this.deployer.privateKeyHex);
        const payload = {
          data,
          deployer: this.deployer.publicKeyHex,
          signature: signed.signatureHex,
          sigAlgorithm: 'secp256k1',
        };
        try {
          const text = await this._request('/api/v1/deploy', { method: 'POST', body: payload });
          const deployId = parseDeployResponse(text);
          return { deployId, data, signedHash: signed.hashHex, term };
        } catch (error) {
          const looksLikeFunds = /phlo|balance|insufficient|pre-?charge|\bREV\b/i.test(
            `${error.message} ${error.body || ''}`,
          );
          if (attempt === 0 && looksLikeFunds && this.faucetEnabled) {
            this._funded = null;
            await this._ensureFunded();
            continue;
          }
          throw error;
        }
      }
      throw new RholoWebError('deploy failed after refuelling', { code: 'deploy-failed' });
    });
  }

  async waitForDeploy(deployId, { timeoutMs = this.deployWaitMs, intervalMs = 500 } = {}) {
    const deadline = Date.now() + timeoutMs;
    let last = { state: 'pending', status: 'not processed' };
    while (Date.now() < deadline) {
      try {
        const document = await this.getDeployStatus(deployId);
        last = parseDeployStatus(document);
        if (last.state === 'success' || last.state === 'error') return last;
      } catch (error) {
        if (error.status === 404) {
          last = { state: 'pending', status: 'not found yet' };
        } else {
          last = { state: 'pending', status: error.message };
        }
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    return { ...last, state: 'timeout', error: `deploy did not finish within ${timeoutMs}ms` };
  }

  async anchorValue(name, value, { onProgress = () => {} } = {}) {
    const term = makeAnchorTerm(name, value);
    onProgress({ step: 'submitting', name });
    const submittedAt = new Date().toISOString();
    const submitted = await this.submitDeploy(term);
    onProgress({ step: 'submitted', deployId: submitted.deployId, submittedAt });

    const executed = await this.waitForDeploy(submitted.deployId);
    if (executed.state !== 'success') {
      throw new RholoWebError(
        `the anchor deploy did not execute: ${executed.error || executed.state}`,
        { code: 'anchor-not-executed', body: JSON.stringify(executed) },
      );
    }
    const block = executed.block;
    onProgress({ step: 'executed', deployId: submitted.deployId, block });
    onProgress({ step: 'included', block });

    const observed = await this.getDataAtName(name, block.blockHash);
    const visible = observed.values.includes(value);
    if (!visible) {
      throw new RholoWebError(
        'the deploy executed but the anchor value was not observed at the name in its block',
        { code: 'anchor-not-observed' },
      );
    }
    onProgress({ step: 'observed', block, name });
    return {
      name,
      valueHash: await sha256B64url(value),
      deployId: submitted.deployId,
      submittedAt,
      confirmedAt: new Date().toISOString(),
      blockHash: block.blockHash,
      blockNumber: block.blockNumber,
      preStateHash: block.preStateHash || null,
      postStateHash: block.postStateHash || null,
      visible,
      term,
    };
  }

  async anchorEvent(did, event, { onProgress = () => {} } = {}) {
    const name = anchorName(did);
    const value = b64url(utf8(JSON.stringify(event)));
    const receipt = await this.anchorValue(name, value, { onProgress });
    return {
      ...receipt,
      kind: 'anchor',
      did,
      eventId: event.id,
      eventSeq: event.seq,
      eventType: event.type,
      event,
    };
  }

  async readDidEvents(did) {
    const name = anchorName(did);
    const read = await this.readName(name);
    const events = [];
    const invalid = [];
    for (const value of read.values) {
      try {
        const decoded = new TextDecoder().decode(unb64url(value));
        events.push(JSON.parse(decoded));
      } catch {
        invalid.push(value.slice(0, 120));
      }
    }
    return { name, events, invalid, values: read.values, block: read.block };
  }

  async resolveDid(did) {
    const read = await this.readDidEvents(did);
    const resolution = await reduceEvents(did, read.events);
    return {
      ...resolution,
      block: read.block,
      invalidValues: read.invalid,
      anchor: read.name,
    };
  }
}
