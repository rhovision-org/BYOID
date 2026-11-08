// Public REV-address proof cards.
//
// A card binds a secp256k1 REV address to a did:byoid controller and lists the
// provider proofs that controller has anchored. The card is signed twice:
//
//   * by the DID's P-256 key (issuer/controller signature), and
//   * by the REV address's secp256k1 key (proof of address control).
//
// Cards are written under the public rholo name byoid:rev:<address>. The
// contract in contracts/rev-proof-registry.rho indexes the latest card for
// Rholang consumers; readers verify signatures rather than trusting the name.

import {
  b64url,
  canonicalize,
  hashField,
  isRevAddress,
  sha256B64url,
  unb64url,
  utf8,
  verifyEs256,
  verifyJws,
} from './shared.js';
import { blake2b, secp256k1 } from './vendor/rholo-crypto.js';
import { revAddressFromPublicKey } from './rholo-web.js';

const CARD_TYPE = 'byoid.rev.proofs';
const CARD_VERSION = 1;
const DER_SIGNATURE_RE = /^[0-9a-f]+$/i;

function hexToBytes(value) {
  const text = String(value || '');
  if (!DER_SIGNATURE_RE.test(text) || text.length % 2 !== 0) {
    throw new Error('expected a hex byte string');
  }
  return Uint8Array.from(text.match(/../g).map((pair) => Number.parseInt(pair, 16)));
}

function bytesToHex(bytes) {
  return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
}

export function revKeyFromPrivateKey(privateKeyHex) {
  const privateKey = hexToBytes(privateKeyHex);
  if (privateKey.length !== 32 || !secp256k1.utils.isValidPrivateKey(privateKey)) {
    throw new Error('invalid secp256k1 private key');
  }
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return {
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
    address: revAddressFromPublicKey(publicKey),
    createdAt: new Date().toISOString(),
  };
}

export function generateRevKey() {
  return revKeyFromPrivateKey(bytesToHex(secp256k1.utils.randomPrivateKey()));
}

/** Sign canonical bytes with a REV key. The digest is BLAKE2b-256, like rholo deploys. */
export function signRevProof(privateKeyHex, bytes) {
  const digest = blake2b(bytes, { dkLen: 32 });
  const signature = secp256k1.sign(digest, hexToBytes(privateKeyHex));
  const der =
    typeof signature.toDERRawBytes === 'function'
      ? signature.toDERRawBytes()
      : hexToBytes(signature.toDERHex());
  return b64url(der);
}

export function verifyRevProof(publicKeyHex, bytes, signatureB64url) {
  try {
    const publicKey = hexToBytes(publicKeyHex);
    if (publicKey.length !== 65 || publicKey[0] !== 0x04) return false;
    const digest = blake2b(bytes, { dkLen: 32 });
    return secp256k1.verify(unb64url(signatureB64url), digest, publicKey);
  } catch {
    return false;
  }
}

export function proofCardBody({
  revAddress,
  revPublicKey,
  did,
  proofs,
  issuedAt = new Date().toISOString(),
  network = null,
  shardId = null,
  agentFingerprint = null,
}) {
  return {
    v: CARD_VERSION,
    type: CARD_TYPE,
    revAddress,
    revPublicKey,
    did,
    network,
    shardId,
    issuedAt,
    agentFingerprint,
    proofs,
  };
}

function addCheck(checks, id, label, ok, detail = '') {
  checks.push({ id, label, ok: Boolean(ok), detail });
  return Boolean(ok);
}

/**
 * Verify a proof card against the DID resolution for card.did and the agent
 * public key currently trusted by this BYOID deployment.
 */
export async function verifyProofCard({ card, address, resolution, agent }) {
  const checks = [];
  const errors = [];
  const proofs = [];
  if (!card || typeof card !== 'object') {
    return { ok: false, checks, errors: ['proof card is not an object'], proofs };
  }
  const { didSignature, revSignature, ...body } = card;
  const bytes = utf8(canonicalize(body));

  addCheck(checks, 'card-type', 'Card is a BYOID REV proof card', card.type === CARD_TYPE && card.v === CARD_VERSION);
  addCheck(
    checks,
    'address-match',
    'Card names the requested REV address',
    card.revAddress === address && isRevAddress(card.revAddress),
  );

  let addressOk = false;
  try {
    const publicKey = hexToBytes(card.revPublicKey);
    addressOk =
      publicKey.length === 65 &&
      publicKey[0] === 0x04 &&
      revAddressFromPublicKey(publicKey) === card.revAddress;
  } catch {
    addressOk = false;
  }
  addCheck(checks, 'rev-address-key', 'REV public key derives the address', addressOk);

  const revOk = verifyRevProof(card.revPublicKey, bytes, revSignature);
  addCheck(checks, 'rev-signature', 'REV key signed the card', revOk);

  const didOk =
    resolution?.status?.valid && typeof didSignature === 'string'
      ? await verifyEs256(resolution.publicKeyJwk, bytes, unb64url(didSignature))
      : false;
  addCheck(
    checks,
    'did-signature',
    'DID key signed the card',
    didOk,
    didOk ? '' : 'DID resolution is invalid or the signature does not verify',
  );

  addCheck(
    checks,
    'did-resolution',
    'DID log resolves on this rnode',
    Boolean(resolution?.status?.valid),
    resolution?.status?.errors?.join(' · ') || '',
  );
  addCheck(checks, 'not-deactivated', 'DID is not deactivated', !resolution?.status?.deactivated);
  addCheck(
    checks,
    'agent-fingerprint',
    'Card names the trusted link agent',
    !card.agentFingerprint || card.agentFingerprint === agent?.fingerprint,
    card.agentFingerprint || '',
  );

  const resolutionLinks = Array.isArray(resolution?.links) ? resolution.links : [];
  const claimedProofs = Array.isArray(card.proofs) ? card.proofs.slice(0, 20) : [];
  if (!Array.isArray(card.proofs)) {
    errors.push('card.proofs must be an array');
  }

  for (const [index, proof] of claimedProofs.entries()) {
    const label = proof?.provider ? `${proof.provider} proof` : `proof ${index + 1}`;
    const proofChecks = [];
    const proofErrors = [];
    if (!proof || typeof proof !== 'object') {
      proofErrors.push('proof is not an object');
    } else {
      const jws = await verifyJws(agent?.publicJwk, proof.attestation);
      if (!jws.ok) proofErrors.push('agent attestation signature does not verify');
      const payload = jws.payload || {};
      if (payload.sub !== card.did) proofErrors.push('attestation subject is a different DID');
      if (payload.provider !== proof.provider) proofErrors.push('attestation provider mismatch');
      if (payload.providerSubjectHash !== proof.subjectHash) {
        proofErrors.push('provider subject hash mismatch');
      }
      if (proof.attestationHash !== (await sha256B64url(proof.attestation))) {
        proofErrors.push('attestation hash mismatch');
      }
      if (proof.handle) {
        const expected = await hashField('handle', proof.handle);
        if (payload.handleHash !== expected) proofErrors.push('handle hash mismatch');
      } else if (payload.handleHash) {
        proofErrors.push('card omits a handle the attestation commits to');
      }
      const link = resolutionLinks.find((candidate) =>
        proof.linkEventId
          ? candidate.eventId === proof.linkEventId
          : candidate.provider === proof.provider &&
            candidate.subjectHash === proof.subjectHash &&
            candidate.attestationHash === proof.attestationHash,
      );
      if (!link) {
        proofErrors.push('link event is not in the canonical DID log');
      } else {
        if (link.provider !== proof.provider) proofErrors.push('link provider mismatch');
        if (link.subjectHash !== proof.subjectHash) proofErrors.push('link subject hash mismatch');
        if (link.attestationHash !== proof.attestationHash) {
          proofErrors.push('link attestation hash mismatch');
        }
        if (proof.linkEventId && link.eventId !== proof.linkEventId) {
          proofErrors.push('link event id mismatch');
        }
      }
      if (payload.demo && proof.demo !== true) {
        // A demo attestation may be displayed, but it must be labelled as demo.
        proofChecks.push({ id: 'demo-label', label: 'Attestation marked as demo', ok: false });
      }
    }
    const ok = proofErrors.length === 0;
    addCheck(
      checks,
      `proof-${index}`,
      label,
      ok,
      proofErrors.join(' · ') || `${proof?.provider || 'provider'} · ${proof?.handle || 'hash only'}`,
    );
    if (!ok) errors.push(`${label}: ${proofErrors.join(' · ')}`);
    if (ok) {
      proofs.push({
        ...proof,
        demo: Boolean(body.proofs[index]?.demo),
      });
    }
  }

  if (!claimedProofs.length) {
    errors.push('card contains no provider proofs');
    addCheck(checks, 'proof-count', 'Card contains provider proofs', false, 'no proofs are listed');
  } else {
    addCheck(checks, 'proof-count', 'Card contains provider proofs', true, `${claimedProofs.length} proof(s)`);
  }

  if (checks.some((check) => !check.ok) && !errors.length) {
    errors.push('one or more proof checks failed');
  }
  return { ok: checks.every((check) => check.ok), checks, errors, proofs, body };
}

export function accountUrl(provider, handle) {
  if (!handle) return null;
  const value = String(handle);
  if (provider === 'github' && /^[A-Za-z0-9-]+$/.test(value)) {
    return `https://github.com/${value}`;
  }
  if (provider === 'facebook' && /^[A-Za-z0-9._-]+$/.test(value)) {
    return `https://www.facebook.com/${value}`;
  }
  return null;
}

export { CARD_TYPE, CARD_VERSION, bytesToHex, hexToBytes };
