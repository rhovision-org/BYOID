import test from 'node:test';
import assert from 'node:assert/strict';

import { generateAgentKey, jwsSign } from '../src/crypto.js';
import {
  canonicalize,
  didFromPublicJwk,
  hashField,
  providerSubjectHash,
  publicJwkOf,
  sha256B64url,
  signEs256,
  utf8,
} from '../public/shared.js';
import {
  generateRevKey,
  proofCardBody,
  signRevProof,
  verifyProofCard,
  verifyRevProof,
} from '../public/rev-proof.js';

async function makeCard({ tamper = false } = {}) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const publicKeyJwk = publicJwkOf(await crypto.subtle.exportKey('jwk', pair.publicKey));
  const did = await didFromPublicJwk(publicKeyJwk);
  const revKey = generateRevKey();
  const agent = await generateAgentKey();
  const provider = 'github';
  const handle = 'octocat';
  const subjectHash = await providerSubjectHash(provider, 'github-subject-1');
  const attestation = await jwsSign(agent.privateJwk, 'byoid-agent-1', {
    iss: 'byoid:agent',
    sub: did,
    aud: 'byoid.verifier',
    provider,
    providerSubjectHash: subjectHash,
    handleHash: await hashField('handle', handle),
    emailHash: null,
    emailVerified: false,
    nameHash: null,
    avatarHash: null,
    demo: false,
  });
  const attestationHash = await sha256B64url(attestation);
  const body = proofCardBody({
    revAddress: revKey.address,
    revPublicKey: revKey.publicKeyHex,
    did,
    proofs: [
      {
        provider,
        handle,
        subjectHash,
        attestation,
        attestationHash,
        linkEventId: 'event-1',
        linkedAt: new Date().toISOString(),
        demo: false,
      },
    ],
    network: 'playground',
    shardId: '/playground',
    agentFingerprint: `sha256:${await sha256B64url(canonicalize(agent.publicJwk))}`,
  });
  if (tamper) body.proofs[0].handle = 'mallory';
  const bytes = utf8(canonicalize(body));
  const card = {
    ...body,
    didSignature: Buffer.from(await signEs256(pair.privateKey, bytes)).toString('base64url'),
    revSignature: signRevProof(revKey.privateKeyHex, bytes),
  };
  const resolution = {
    status: { valid: true, deactivated: false, errors: [] },
    publicKeyJwk,
    links: [
      {
        eventId: 'event-1',
        provider,
        subjectHash,
        attestationHash,
        linkedAt: body.proofs[0].linkedAt,
      },
    ],
  };
  const agentInfo = {
    publicJwk: agent.publicJwk,
    fingerprint: `sha256:${await sha256B64url(canonicalize(agent.publicJwk))}`,
  };
  return { card, revKey, resolution, agentInfo, bodyBytes: bytes };
}

test('REV proof cards verify with both keys and an anchored link', async () => {
  const { card, revKey, resolution, agentInfo, bodyBytes } = await makeCard();
  // Sanity-check the raw REV signature primitive separately.
  assert.equal(verifyRevProof(revKey.publicKeyHex, bodyBytes, card.revSignature), true);
  const result = await verifyProofCard({
    card,
    address: revKey.address,
    resolution,
    agent: agentInfo,
  });
  assert.equal(result.ok, true);
  assert.equal(result.proofs.length, 1);
  assert.equal(result.errors.length, 0);
});

test('REV proof card verification rejects a changed handle', async () => {
  const { card, revKey, resolution, agentInfo } = await makeCard({ tamper: true });
  const result = await verifyProofCard({
    card,
    address: revKey.address,
    resolution,
    agent: agentInfo,
  });
  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'proof-0').ok, false);
});
