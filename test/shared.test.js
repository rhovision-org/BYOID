import test from 'node:test';
import assert from 'node:assert/strict';

import {
  anchorName,
  b64url,
  base58Decode,
  base58Encode,
  buildDIDDocument,
  canonicalize,
  didFromPublicJwk,
  eventBody,
  EVENT_TYPES,
  finalizeEvent,
  hashField,
  isDid,
  providerSubjectHash,
  publicJwkOf,
  reduceEvents,
  sha256B64url,
  signEs256,
  unb64url,
  utf8,
  validateEventShape,
  verifyCredential,
  verifyEventSignature,
  verifyPresentation,
} from '../public/shared.js';
import { jwsSign } from '../src/crypto.js';

async function makeKey() {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const publicJwk = publicJwkOf(await crypto.subtle.exportKey('jwk', pair.publicKey));
  const did = await didFromPublicJwk(publicJwk);
  return { pair, privateJwk, publicJwk, did };
}

async function signedEvent(did, privateKey, body) {
  const signature = await signEs256(privateKey, utf8(canonicalize(body)));
  return finalizeEvent(body, signature);
}

async function makeChain() {
  const identity = await makeKey();
  const createdAt = '2026-01-01T00:00:00.000Z';
  const didDocument = buildDIDDocument({
    did: identity.did,
    publicJwk: identity.publicJwk,
    serviceEndpoint: 'http://localhost:3000',
    createdAt,
  });
  const create = await signedEvent(identity.did, identity.pair.privateKey, {
    v: 1,
    type: EVENT_TYPES.CREATE,
    did: identity.did,
    seq: 1,
    prev: null,
    at: createdAt,
    payload: {
      publicKeyJwk: identity.publicJwk,
      didDocument,
      method: { chain: 'rholo', name: anchorName(identity.did) },
    },
  });
  const resolution = await reduceEvents(identity.did, [create]);
  assert.equal(resolution.status.valid, true);
  return { ...identity, create, resolution };
}

test('canonicalize is deterministic and drops undefined members', () => {
  const left = { b: 2, a: { d: 4, c: [3, 1] }, skip: undefined };
  const right = { a: { c: [3, 1], d: 4 }, b: 2 };
  assert.equal(canonicalize(left), canonicalize(right));
  assert.equal(canonicalize(left), '{"a":{"c":[3,1],"d":4},"b":2}');
});

test('base58 round-trips arbitrary bytes', () => {
  for (const bytes of [
    new Uint8Array([0, 0, 1, 2, 3]),
    crypto.getRandomValues(new Uint8Array(32)),
  ]) {
    assert.deepEqual(base58Decode(base58Encode(bytes)), bytes);
  }
});

test('a DID is derived from its P-256 public key', async () => {
  const { publicJwk, did } = await makeKey();
  assert.equal(await didFromPublicJwk(publicJwk), did);
  assert.equal(isDid(did), true);
  assert.equal(did.length > 40, true);
  assert.equal(anchorName(did), `byoid:did:${did.slice('did:byoid:'.length)}`);
});

test('create, link and revoke events form a verified hash-linked chain', async () => {
  const chain = await makeChain();
  const subjectHash = await providerSubjectHash('google', 'subject-1');
  const attestationHash = await sha256B64url('attestation');
  const linkedAt = '2026-01-02T00:00:00.000Z';
  const link = await signedEvent(chain.did, chain.pair.privateKey, {
    v: 1,
    type: EVENT_TYPES.LINK,
    did: chain.did,
    seq: 2,
    prev: chain.create.id,
    at: linkedAt,
    payload: { provider: 'google', subjectHash, attestationHash, linkedAt },
  });
  const revoke = await signedEvent(chain.did, chain.pair.privateKey, {
    v: 1,
    type: EVENT_TYPES.REVOKE,
    did: chain.did,
    seq: 3,
    prev: link.id,
    at: '2026-01-03T00:00:00.000Z',
    payload: {
      credentialId: 'urn:uuid:test',
      revokedAt: '2026-01-03T00:00:00.000Z',
      reason: 'test',
    },
  });

  const resolution = await reduceEvents(chain.did, [chain.create, link, revoke]);
  assert.equal(resolution.status.valid, true);
  assert.equal(resolution.status.eventCount, 3);
  assert.equal(resolution.status.latestSeq, 3);
  assert.equal(resolution.links.length, 1);
  assert.equal(resolution.revocations.length, 1);
  assert.equal(resolution.revocations[0].credentialId, 'urn:uuid:test');
  assert.equal(resolution.didDocument.byoid.links[0].subjectHash, subjectHash);
  assert.equal(JSON.stringify(resolution.didDocument).includes('subject-1'), false);
});

test('the resolver rejects tampered events and warns about gaps', async () => {
  const chain = await makeChain();
  const tampered = JSON.parse(JSON.stringify(chain.create));
  tampered.at = '2026-02-01T00:00:00.000Z';
  const resolution = await reduceEvents(chain.did, [tampered]);
  assert.equal(resolution.status.valid, false);
  assert.equal(resolution.status.rejectedCount, 1);

  const orphan = await signedEvent(chain.did, chain.pair.privateKey, {
    v: 1,
    type: EVENT_TYPES.LINK,
    did: chain.did,
    seq: 3,
    prev: 'A'.repeat(43),
    at: '2026-01-03T00:00:00.000Z',
    payload: {
      provider: 'google',
      subjectHash: await providerSubjectHash('google', 'x'),
      attestationHash: await sha256B64url('x'),
      linkedAt: '2026-01-03T00:00:00.000Z',
    },
  });
  const gapResolution = await reduceEvents(chain.did, [chain.create, orphan]);
  assert.equal(gapResolution.status.valid, true);
  assert.equal(gapResolution.status.gaps, true);
  assert.equal(gapResolution.status.eventCount, 1);
});

test('a credential verifies only when every disclosed field matches the attestation', async () => {
  const chain = await makeChain();
  const agent = await makeKey();
  const subject = 'demo-google-subject';
  const subjectHash = await providerSubjectHash('google', subject);
  const linkedAt = '2026-01-02T00:00:00.000Z';
  const email = 'Alice@Example.com';
  const payload = {
    iss: 'byoid:agent',
    sub: chain.did,
    aud: 'byoid.verifier',
    iat: Math.floor(Date.parse(linkedAt) / 1000),
    jti: 'test-jti',
    provider: 'google',
    providerSubjectHash: subjectHash,
    handleHash: await hashField('handle', 'alice'),
    emailHash: await hashField('email', email),
    emailVerified: true,
    nameHash: await hashField('name', 'Alice'),
    avatarHash: null,
    demo: true,
  };
  const attestation = await jwsSign(agent.privateJwk, 'byoid-agent-1', payload);
  const attestationHash = await sha256B64url(attestation);
  const link = await signedEvent(chain.did, chain.pair.privateKey, {
    v: 1,
    type: EVENT_TYPES.LINK,
    did: chain.did,
    seq: 2,
    prev: chain.create.id,
    at: linkedAt,
    payload: { provider: 'google', subjectHash, attestationHash, linkedAt },
  });
  const resolution = await reduceEvents(chain.did, [chain.create, link]);
  assert.equal(resolution.status.valid, true);

  const account = {
    provider: 'google',
    subjectHash,
    attestationHash,
    attestation,
    handle: 'alice',
    email,
    emailVerified: true,
    verifiedAt: linkedAt,
  };
  const credential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: 'urn:uuid:credential-1',
    type: ['VerifiableCredential', 'BYOIDAccountCredential'],
    issuer: chain.did,
    issuanceDate: '2026-01-02T00:00:00.000Z',
    credentialSubject: { id: chain.did, accounts: [account] },
  };
  const proof = await signEs256(chain.pair.privateKey, utf8(canonicalize(credential)));
  credential.proof = {
    type: 'JsonWebSignature2020',
    created: '2026-01-02T00:00:00.000Z',
    verificationMethod: `${chain.did}#key-1`,
    proofPurpose: 'assertionMethod',
    jws: b64url(proof),
  };

  const verified = await verifyCredential({
    credential,
    resolution,
    agentPublicJwk: agent.publicJwk,
  });
  assert.equal(verified.ok, true, JSON.stringify(verified.errors));
  assert.equal(verified.claims[0].email, email);
  assert.equal(verified.claims[0].demo, true);

  const tampered = JSON.parse(JSON.stringify(credential));
  tampered.credentialSubject.accounts[0].email = 'attacker@example.com';
  delete tampered.proof;
  tampered.proof = {
    ...credential.proof,
    jws: b64url(await signEs256(chain.pair.privateKey, utf8(canonicalize(tampered)))),
  };
  const tamperedResult = await verifyCredential({
    credential: tampered,
    resolution,
    agentPublicJwk: agent.publicJwk,
  });
  assert.equal(tamperedResult.ok, false);
  assert.equal(
    tamperedResult.checks.find((check) => check.id === 'fields-0')?.ok,
    false,
  );
});

test('a presentation verifies, and the holder signature is required', async () => {
  const chain = await makeChain();
  const agent = await makeKey();
  const subjectHash = await providerSubjectHash('github', 'octo');
  const linkedAt = '2026-01-02T00:00:00.000Z';
  const attestation = await jwsSign(agent.privateJwk, 'byoid-agent-1', {
    iss: 'byoid:agent',
    sub: chain.did,
    aud: 'byoid.verifier',
    iat: Math.floor(Date.parse(linkedAt) / 1000),
    jti: 'j',
    provider: 'github',
    providerSubjectHash: subjectHash,
    handleHash: await hashField('handle', 'octo'),
    emailHash: null,
    emailVerified: false,
    nameHash: null,
    avatarHash: null,
    demo: true,
  });
  const attestationHash = await sha256B64url(attestation);
  const link = await signedEvent(chain.did, chain.pair.privateKey, {
    v: 1,
    type: EVENT_TYPES.LINK,
    did: chain.did,
    seq: 2,
    prev: chain.create.id,
    at: linkedAt,
    payload: { provider: 'github', subjectHash, attestationHash, linkedAt },
  });
  const resolution = await reduceEvents(chain.did, [chain.create, link]);

  const credential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: 'urn:uuid:credential-2',
    type: ['VerifiableCredential', 'BYOIDAccountCredential'],
    issuer: chain.did,
    issuanceDate: linkedAt,
    credentialSubject: {
      id: chain.did,
      accounts: [
        {
          provider: 'github',
          subjectHash,
          attestationHash,
          attestation,
          handle: 'octo',
          emailVerified: false,
          verifiedAt: linkedAt,
        },
      ],
    },
  };
  credential.proof = {
    type: 'JsonWebSignature2020',
    created: linkedAt,
    verificationMethod: `${chain.did}#key-1`,
    proofPurpose: 'assertionMethod',
    jws: b64url(await signEs256(chain.pair.privateKey, utf8(canonicalize(credential)))),
  };

  const presentation = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: 'urn:uuid:presentation-1',
    type: ['VerifiablePresentation', 'BYOIDPresentation'],
    holder: chain.did,
    created: linkedAt,
    verifiableCredential: [credential],
  };
  presentation.proof = {
    type: 'JsonWebSignature2020',
    created: linkedAt,
    verificationMethod: `${chain.did}#key-1`,
    proofPurpose: 'authentication',
    jws: b64url(await signEs256(chain.pair.privateKey, utf8(canonicalize(presentation)))),
  };

  const resolveDid = async () => resolution;
  const verified = await verifyPresentation({
    presentation,
    resolveDid,
    agentPublicJwk: agent.publicJwk,
  });
  assert.equal(verified.ok, true, JSON.stringify(verified.errors));

  const tampered = JSON.parse(JSON.stringify(presentation));
  tampered.holder = (await makeKey()).did;
  const tamperedResult = await verifyPresentation({
    presentation: tampered,
    resolveDid,
    agentPublicJwk: agent.publicJwk,
  });
  assert.equal(tamperedResult.ok, false);
});

test('event shape validation rejects a bad signature length and a mismatched DID', async () => {
  const { did, publicJwk, pair } = await makeKey();
  const body = {
    v: 1,
    type: EVENT_TYPES.CREATE,
    did,
    seq: 1,
    prev: null,
    at: new Date().toISOString(),
    payload: { publicKeyJwk: publicJwk },
  };
  const event = await signedEvent(did, pair.privateKey, body);
  validateEventShape(event);
  assert.equal(await verifyEventSignature(publicJwk, event), true);
  const withBadSig = { ...event, signature: 'abc' };
  assert.throws(() => validateEventShape(withBadSig), /signature/);
  const withWrongDid = { ...event, did: 'did:byoid:z111111111111111111111111111111' };
  const resolution = await reduceEvents(withWrongDid.did, [withWrongDid]);
  assert.equal(resolution.status.valid, false);
});

test('event bodies are detached from id and signature without mutating the event', async () => {
  const { did, publicJwk, pair } = await makeKey();
  const event = await signedEvent(did, pair.privateKey, {
    v: 1,
    type: EVENT_TYPES.CREATE,
    did,
    seq: 1,
    prev: null,
    at: new Date().toISOString(),
    payload: { publicKeyJwk: publicJwk },
  });
  const body = eventBody(event);
  assert.equal('id' in body, false);
  assert.equal('signature' in body, false);
  assert.equal(event.id.length > 40, true);
  assert.deepEqual(unb64url(b64url(utf8('hello'))), utf8('hello'));
});
