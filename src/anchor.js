// Anchor validation and serialized writes.
//
// A public tuple-space name is a bulletin board: anyone can write to it. The
// security property is not write access, it is that every event is signed by
// the DID key and hash-linked to its predecessor. This service re-checks that
// property before spending phlo, and serializes writes so two events cannot
// race for the same sequence number in one server process.

import {
  anchorName,
  didFromPublicJwk,
  eventId,
  isDid,
  validateEventShape,
  verifyEventSignature,
} from '../public/shared.js';
import { PROVIDER_IDS } from './providers.js';

export class AnchorError extends Error {
  constructor(code, message, { status = 400, resolution = null } = {}) {
    super(message);
    this.name = 'AnchorError';
    this.code = code;
    this.status = status;
    this.resolution = resolution;
  }
}

export class AnchorService {
  constructor({ client, cacheTtlMs = 3000 }) {
    this.client = client;
    this.cacheTtlMs = cacheTtlMs;
    this.cache = new Map();
    this.inflight = new Map();
    this.lockTail = Promise.resolve();
  }

  invalidate(did) {
    if (did) this.cache.delete(did);
    else this.cache.clear();
  }

  async resolve(did, { force = false } = {}) {
    if (!isDid(did)) throw new AnchorError('invalid-did', 'not a did:byoid identifier', { status: 400 });
    if (!force) {
      const cached = this.cache.get(did);
      if (cached && Date.now() - cached.at < this.cacheTtlMs) return cached.value;
    }
    if (this.inflight.has(did)) return this.inflight.get(did);
    const promise = this.client
      .resolveDid(did)
      .then((resolution) => {
        this.cache.set(did, { at: Date.now(), value: resolution });
        return resolution;
      })
      .finally(() => this.inflight.delete(did));
    this.inflight.set(did, promise);
    try {
      return await promise;
    } catch (error) {
      throw new AnchorError(
        'chain-unavailable',
        `could not read the rholo anchor: ${error.message}`,
        { status: 502 },
      );
    }
  }

  /** Validate an event against the current chain without writing it. */
  async inspect(did, event, { force = true } = {}) {
    try {
      validateEventShape(event);
    } catch (error) {
      throw new AnchorError('invalid-event', error.message, { status: 400 });
    }
    if (event.did !== did) {
      throw new AnchorError('did-mismatch', 'event.did does not match the requested DID');
    }
    const expectedId = await eventId(event);
    if (event.id !== expectedId) {
      throw new AnchorError('bad-event-id', 'event id is not the hash of its content');
    }

    if (event.type === 'byoid.did.create') {
      const derived = await didFromPublicJwk(event.payload.publicKeyJwk);
      if (derived !== did) {
        throw new AnchorError('did-key-mismatch', 'DID is not derived from the create event key');
      }
      if (!(await verifyEventSignature(event.payload.publicKeyJwk, event))) {
        throw new AnchorError('bad-signature', 'create event signature does not verify');
      }
      const resolution = await this.resolve(did, { force: true });
      if (resolution.status.valid) {
        if (resolution.createEvent?.id === event.id) {
          return { ok: true, alreadyAnchored: true, resolution };
        }
        throw new AnchorError(
          'did-already-exists',
          'this DID already has a different create event on chain',
          { status: 409, resolution },
        );
      }
      return { ok: true, resolution };
    }

    const resolution = await this.resolve(did, { force });
    if (!resolution.status.valid) {
      throw new AnchorError('did-not-found', 'no valid create event for this DID', {
        status: 404,
        resolution,
      });
    }
    if (resolution.deactivated) {
      throw new AnchorError('did-deactivated', 'this DID has been deactivated', {
        status: 409,
        resolution,
      });
    }
    if (resolution.events.some((candidate) => candidate.id === event.id)) {
      return { ok: true, alreadyAnchored: true, resolution };
    }
    if (event.seq !== resolution.status.latestSeq + 1) {
      throw new AnchorError(
        'stale-sequence',
        `event seq ${event.seq} does not extend the chain tip (${resolution.status.latestSeq}); re-sign and retry`,
        { status: 409, resolution },
      );
    }
    if (event.prev !== resolution.status.latestEventId) {
      throw new AnchorError(
        'stale-sequence',
        'event prev does not point at the current chain tip; re-sign and retry',
        { status: 409, resolution },
      );
    }
    if (!(await verifyEventSignature(resolution.publicKeyJwk, event))) {
      throw new AnchorError('bad-signature', 'event signature does not verify with the DID key', {
        status: 400,
        resolution,
      });
    }
    if (event.type === 'byoid.identity.link' && !PROVIDER_IDS.includes(event.payload.provider)) {
      throw new AnchorError(
        'provider-not-supported',
        `unsupported identity provider: ${event.payload.provider}`,
      );
    }
    return { ok: true, resolution };
  }

  async withLock(fn) {
    const previous = this.lockTail;
    let release;
    this.lockTail = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  /**
   * Validate under the write lock, anchor, then read the result back and prove
   * the event is in the canonical chain before reporting success.
   */
  async run(did, event, { onProgress = () => {} } = {}) {
    return this.withLock(async () => {
      onProgress({ step: 'validating' });
      const inspection = await this.inspect(did, event, { force: true });
      if (inspection.alreadyAnchored) {
        onProgress({ step: 'validated', resolution: inspection.resolution });
        return { alreadyAnchored: true, resolution: inspection.resolution };
      }
      onProgress({ step: 'validated', resolution: inspection.resolution });
      const receipt = await this.client.anchorEvent(did, event, { onProgress });
      this.invalidate(did);
      let resolution;
      try {
        resolution = await this.resolve(did, { force: true });
      } catch (error) {
        throw new AnchorError(
          'anchor-confirmation-failed',
          `the deploy landed but reading it back failed: ${error.message}`,
          { status: 502 },
        );
      }
      if (!resolution.events.some((candidate) => candidate.id === event.id)) {
        throw new AnchorError(
          'anchor-not-in-chain',
          'the deploy executed but the event is not in the canonical chain (another writer may have forked it)',
          { status: 409, resolution },
        );
      }
      return { receipt, resolution };
    });
  }

  anchorNameFor(did, prefix = 'byoid') {
    return anchorName(did, prefix);
  }
}
