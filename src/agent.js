// The BYOID demo agent. It verifies OAuth profiles and signs compact ES256
// attestations over *hashes* of the claims, so a credential can disclose an
// email without the attestation itself containing one.
//
// The agent key is independent of the rholo deploy key: the deploy key pays
// phlo, the agent key speaks for the identity-link service.

import {
  base64url,
  jwkFingerprint,
  jwsSign,
  jwsVerify,
  randomBase64Url,
  sha256B64url,
  signEs256,
  unb64url,
  utf8,
  verifyEs256,
} from './crypto.js';
import {
  canonicalize,
  hashField,
  isValidPublicJwk,
  providerSubjectHash,
  publicJwkOf,
} from '../public/shared.js';

export class Agent {
  constructor({ key, client = null, agentName = 'byoid:agent:key', enabled = true }) {
    this.privateJwk = key.privateJwk;
    this.publicJwk = publicJwkOf(key.publicJwk);
    this.createdAt = key.createdAt || new Date().toISOString();
    this.issuer = 'byoid:agent';
    this.kid = 'byoid-agent-1';
    this.client = client;
    this.agentName = agentName;
    this.enabled = enabled;
    this.fingerprint = jwkFingerprint(this.publicJwk);
    this.anchorStatus = enabled ? 'idle' : 'disabled';
    this.chainAnchor = null;
    this.anchorError = null;
    this._anchorPromise = null;
  }

  publicInfo() {
    return {
      issuer: this.issuer,
      kid: this.kid,
      publicJwk: this.publicJwk,
      fingerprint: this.fingerprint,
      createdAt: this.createdAt,
      role: 'demo identity-link agent',
      chainAnchor: this.chainAnchor
        ? { ...this.chainAnchor }
        : { status: this.anchorStatus, error: this.anchorError || null, name: this.agentName },
    };
  }

  /**
   * Sign one link attestation. The payload contains stable hashes only; the
   * browser receives the raw profile from the provider flow and decides which
   * fields, if any, to include in a credential.
   */
  async signAttestation(profile, did) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: this.issuer,
      sub: did,
      aud: 'byoid.verifier',
      iat: now,
      jti: randomBase64Url(16),
      provider: profile.provider,
      providerSubjectHash: await providerSubjectHash(profile.provider, profile.subject),
      handleHash: profile.handle ? await hashField('handle', profile.handle) : null,
      emailHash: profile.email ? await hashField('email', profile.email) : null,
      emailVerified: Boolean(profile.emailVerified),
      nameHash: profile.name ? await hashField('name', profile.name) : null,
      avatarHash: profile.avatarUrl ? await hashField('avatarUrl', profile.avatarUrl) : null,
      demo: Boolean(profile.demo),
    };
    const attestation = await jwsSign(this.privateJwk, this.kid, payload);
    return {
      provider: profile.provider,
      subjectHash: payload.providerSubjectHash,
      attestation,
      attestationHash: await sha256B64url(attestation),
      issuedAt: new Date(now * 1000).toISOString(),
      payload,
    };
  }

  async verifyAttestation(compact) {
    const result = await jwsVerify(this.publicJwk, compact);
    if (!result.ok) return { ok: false, error: result.error || 'invalid signature' };
    if (result.header.alg !== 'ES256') return { ok: false, error: 'unexpected JWS algorithm' };
    if (result.header.kid !== this.kid) return { ok: false, error: 'unexpected agent key id' };
    if (result.payload.iss !== this.issuer) return { ok: false, error: 'unexpected issuer' };
    return result;
  }

  /** The signed self-description written once to the playground. */
  async buildAnchorRecord({ network = null, shardId = null } = {}) {
    const body = {
      v: 1,
      type: 'byoid.agent.key',
      issuer: this.issuer,
      kid: this.kid,
      publicJwk: this.publicJwk,
      fingerprint: this.fingerprint,
      createdAt: this.createdAt,
      network,
      shardId,
    };
    const signature = await signEs256(this.privateJwk, utf8(canonicalize(body)));
    return { ...body, signature: base64url(signature) };
  }

  async verifyAnchorRecord(record) {
    if (!record || record.type !== 'byoid.agent.key') return false;
    if (record.issuer !== this.issuer || record.kid !== this.kid) return false;
    if (!isValidPublicJwk(record.publicJwk)) return false;
    const { signature, ...body } = record;
    if (typeof signature !== 'string') return false;
    return verifyEs256(record.publicJwk, utf8(canonicalize(body)), unb64url(signature));
  }

  /**
   * Publish the agent key once. Resolution is read-before-write, so restarts
   * reuse the existing record instead of spending another deploy.
   */
  ensureAnchored() {
    if (!this.enabled || !this.client) {
      this.anchorStatus = 'disabled';
      return Promise.resolve({ status: 'disabled', name: this.agentName });
    }
    if (this._anchorPromise) return this._anchorPromise;
    this.anchorStatus = 'anchoring';
    this._anchorPromise = (async () => {
      const existing = await this.client.readAgentRecord(this.agentName);
      for (const record of existing.records) {
        if (!(await this.verifyAnchorRecord(record))) continue;
        if (jwkFingerprint(record.publicJwk) !== this.fingerprint) continue;
        this.chainAnchor = {
          status: 'existing',
          name: this.agentName,
          recordId: await sha256B64url(canonicalize(record)),
          publicJwk: record.publicJwk,
          blockHash: existing.block?.blockHash || null,
          blockNumber: existing.block?.blockNumber || null,
        };
        this.anchorStatus = 'anchored';
        this.anchorError = null;
        return this.chainAnchor;
      }

      let network = null;
      try {
        network = await this.client.network();
      } catch {
        // The record is still valid without network metadata.
      }
      const record = await this.buildAnchorRecord({
        network: network?.networkId || null,
        shardId: network?.shardId || null,
      });
      const value = base64url(utf8(JSON.stringify(record)));
      const receipt = await this.client.anchorValue(this.agentName, value);
      this.chainAnchor = {
        status: 'anchored',
        name: this.agentName,
        recordId: await sha256B64url(canonicalize(record)),
        publicJwk: record.publicJwk,
        deployId: receipt.deployId,
        blockHash: receipt.blockHash,
        blockNumber: receipt.blockNumber,
        confirmedAt: receipt.confirmedAt,
      };
      this.anchorStatus = 'anchored';
      this.anchorError = null;
      return this.chainAnchor;
    })()
      .catch((error) => {
        this.anchorStatus = 'error';
        this.anchorError = error.message;
        this._anchorPromise = null;
        throw error;
      });
    return this._anchorPromise;
  }
}
