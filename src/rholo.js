// A small rholo HTTP client: discover the chain, sign and submit deploys, follow
// the evidence ladder (submitted → executed → included → observed), and read
// the signed event log back out of the tuple space.

import {
  base64url,
  sha256B64url,
  signDeployData,
  utf8,
} from './crypto.js';
import {
  anchorName,
  reduceEvents,
} from '../public/shared.js';

const DEPLOY_ID_RE = /([0-9a-f]{100,300})/i;
const ANCHOR_NAME_RE = /^[A-Za-z0-9:._-]{1,200}$/;
const ANCHOR_VALUE_RE = /^[A-Za-z0-9_-]{1,20000}$/;

export class RholoError extends Error {
  constructor(message, { code = 'rholo-error', status = null, body = '', retryable = false } = {}) {
    super(message);
    this.name = 'RholoError';
    this.code = code;
    this.status = status;
    this.body = body;
    this.retryable = retryable;
  }
}

/** Rholang for "send this string datum at this public name". */
export function makeAnchorTerm(name, value) {
  if (!ANCHOR_NAME_RE.test(name)) throw new Error('invalid anchor name');
  if (!ANCHOR_VALUE_RE.test(value)) throw new Error('invalid anchor value');
  return `@"${name}"!("${value}")`;
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
  throw new RholoError(`rholo rejected the deploy: ${value.slice(0, 500)}`, {
    code: 'deploy-rejected',
    body: value,
  });
}

/**
 * Decode the `expr` array returned by data-at-name into UTF-8 strings.
 * `RhoExpr` arms wrap their payload in `{ data: … }`.
 */
export function decodeDataValues(exprs) {
  const values = [];
  for (const expr of Array.isArray(exprs) ? exprs : []) {
    if (expr?.ExprString?.data !== undefined) {
      values.push(String(expr.ExprString.data));
    } else if (expr?.ExprBytes?.data !== undefined) {
      try {
        values.push(Buffer.from(expr.ExprBytes.data, 'hex').toString('utf8'));
      } catch {
        // Ignore payloads that are not UTF-8 text.
      }
    }
  }
  return values;
}

export class RholoClient {
  constructor({
    url,
    shardId = null,
    faucet = true,
    deployerKey,
    needsFaucet = true,
    timeoutMs = 25000,
    deployWaitMs = 40000,
    phloLimit = 1_000_000,
    phloPrice = 1,
    fetchImpl = fetch,
    logger = console,
  }) {
    this.url = String(url).replace(/\/+$/, '');
    this.shardId = shardId;
    this.faucetEnabled = faucet;
    this.deployerKey = deployerKey;
    this.needsFaucet = needsFaucet;
    this.timeoutMs = timeoutMs;
    this.deployWaitMs = deployWaitMs;
    this.phloLimit = phloLimit;
    this.phloPrice = phloPrice;
    this.fetchImpl = fetchImpl;
    this.logger = logger;
    this._funded = null;
    this._queue = Promise.resolve();
    this._network = null;
    this._networkAt = 0;
  }

  async _request(path, { method = 'GET', body, headers = {}, timeoutMs = this.timeoutMs } = {}) {
    const url = `${this.url}${path}`;
    const init = {
      method,
      headers: { accept: 'application/json', ...headers },
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
      throw new RholoError(`cannot reach rholo at ${this.url}: ${error.message}`, {
        code: 'network',
        retryable: true,
      });
    }
    const text = await response.text();
    if (!response.ok) {
      throw new RholoError(
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
      throw new RholoError(`rholo ${path} returned non-JSON: ${text.slice(0, 300)}`, {
        code: 'bad-json',
        body: text,
      });
    }
  }

  async getStatus() {
    return this._json('/api/v1/status');
  }

  async getCapabilities() {
    return this._json('/api/v1/capabilities');
  }

  /** Fresh chain identity and height, cached for just over a second. */
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

  async getBlock(hash) {
    if (!/^[0-9a-f]{64}$/i.test(String(hash))) throw new Error('invalid block hash');
    return this._json(`/api/v1/block/${hash}`);
  }

  async getDeployStatus(deployId) {
    if (!/^[0-9a-f]{100,300}$/i.test(String(deployId))) {
      throw new Error('invalid deploy id');
    }
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

  /** Read all data at a public name in the current (latest) state. */
  async readName(name) {
    const block = await this.latestBlock();
    if (!block?.blockHash) throw new RholoError('rholo did not return a latest block', { code: 'no-block' });
    return this.getDataAtName(name, block.blockHash);
  }

  async faucet(address) {
    return this._json('/api/v1/faucet', { method: 'POST', body: { address } });
  }

  _enqueue(fn) {
    const run = this._queue.then(fn, fn);
    this._queue = run.catch(() => {});
    return run;
  }

  async _ensureFunded() {
    if (!this.needsFaucet || !this.faucetEnabled) return;
    if (!this._funded) {
      this._funded = (async () => {
        let response;
        try {
          response = await this.faucet(this.deployerKey.address);
        } catch (error) {
          // The playground faucet refuses a second drip while the previous one
          // is processed but not yet finalized. That means the wallet already
          // received a drip, so the useful response is to proceed and let the
          // deploy itself report whether the balance is sufficient.
          if (/previous drip|finality|already/i.test(`${error.message} ${error.body || ''}`)) {
            this.logger.warn?.('[rholo] faucet already has a drip in flight; assuming the wallet is funded');
            return;
          }
          throw error;
        }
        if (!response?.deployId) {
          throw new RholoError('the rholo faucet did not return a deploy id', {
            code: 'faucet-failed',
            body: JSON.stringify(response),
          });
        }
        if (response.status === 'failed') {
          throw new RholoError(`the rholo faucet failed: ${response.deployError || 'unknown'}`, {
            code: 'faucet-failed',
          });
        }
        const result = await this.waitForDeploy(response.deployId, { timeoutMs: 30000 });
        if (result.state !== 'success') {
          throw new RholoError(
            `the rholo faucet drip did not execute: ${result.error || result.state}`,
            { code: 'faucet-failed' },
          );
        }
        this.logger.info?.(
          `[rholo] faucet funded ${this.deployerKey.address} (deploy ${response.deployId.slice(0, 16)}…)`,
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
        const signed = signDeployData(data, this.deployerKey.privateKeyHex);
        const payload = {
          data,
          deployer: this.deployerKey.publicKeyHex,
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
          if (attempt === 0 && looksLikeFunds && this.needsFaucet && this.faucetEnabled) {
            this._funded = null;
            await this._ensureFunded();
            continue;
          }
          throw error;
        }
      }
      throw new RholoError('deploy failed after refuelling', { code: 'deploy-failed' });
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

  /**
   * Anchor one string value at a public name and climb the evidence ladder:
   * submitted → executed → included → observed at the block that executed it.
   */
  async anchorValue(name, value, { onProgress = () => {} } = {}) {
    const term = makeAnchorTerm(name, value);
    onProgress({ step: 'submitting', name });
    const submittedAt = new Date().toISOString();
    const submitted = await this.submitDeploy(term);
    onProgress({ step: 'submitted', deployId: submitted.deployId, submittedAt });

    const executed = await this.waitForDeploy(submitted.deployId);
    if (executed.state !== 'success') {
      throw new RholoError(
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
      throw new RholoError(
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

  /** Anchor a signed BYOID event at its DID's public name. */
  async anchorEvent(did, event, { onProgress = () => {} } = {}) {
    const name = anchorName(did);
    const value = base64url(utf8(JSON.stringify(event)));
    this.logger.info?.(
      `[rholo] anchoring ${event.type} seq ${event.seq} for ${did.slice(0, 28)}…`,
    );
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

  /** Read and JSON-decode every value at a DID anchor name. */
  async readDidEvents(did) {
    const name = anchorName(did);
    const read = await this.readName(name);
    const events = [];
    const invalid = [];
    for (const value of read.values) {
      try {
        const decoded = new TextDecoder().decode(
          Uint8Array.from(Buffer.from(value, 'base64url')),
        );
        events.push(JSON.parse(decoded));
      } catch {
        invalid.push(value.slice(0, 120));
      }
    }
    return { name, events, invalid, values: read.values, block: read.block };
  }

  /** Resolve a DID from the chain with the shared reduction algorithm. */
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

  async readAgentRecord(name) {
    const read = await this.readName(name);
    const records = [];
    for (const value of read.values) {
      try {
        const decoded = new TextDecoder().decode(
          Uint8Array.from(Buffer.from(value, 'base64url')),
        );
        records.push(JSON.parse(decoded));
      } catch {
        // Not an agent record; ignore.
      }
    }
    return { records, block: read.block, values: read.values };
  }
}
