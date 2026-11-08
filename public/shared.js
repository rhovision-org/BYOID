// Shared BYOID model: canonical JSON, did:byoid derivation, signed event logs,
// DID document reduction, and credential / presentation verification.
//
// This file is loaded by the browser as an ES module AND imported by the Node
// server, so the exact same verification code runs on both sides. It uses only
// WebCrypto and standard ECMAScript — no Node or DOM APIs.

export const DID_METHOD = 'byoid';
export const DID_PREFIX = `did:${DID_METHOD}:`;
export const EVENT_VERSION = 1;
export const MAX_EVENT_BYTES = 16 * 1024;

export const EVENT_TYPES = Object.freeze({
  CREATE: 'byoid.did.create',
  LINK: 'byoid.identity.link',
  REVOKE: 'byoid.credential.revoke',
  DEACTIVATE: 'byoid.did.deactivate',
});

export const EVENT_TYPE_LIST = Object.freeze(Object.values(EVENT_TYPES));

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP = new Map([...BASE58_ALPHABET].map((ch, i) => [ch, BigInt(i)]));
const DID_RE = /^did:byoid:z[1-9A-HJ-NP-Za-km-z]{20,120}$/;

export const utf8 = (value) => new TextEncoder().encode(value);

// ── JSON / base64url ─────────────────────────────────────────────────────────

/** Deterministic JSON: object keys sorted, undefined members omitted. */
export function canonicalize(value) {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('cannot canonicalize a non-finite number');
    return JSON.stringify(value);
  }
  if (type === 'boolean' || type === 'string') return JSON.stringify(value);
  if (type === 'bigint') throw new TypeError('cannot canonicalize a BigInt');
  if (Array.isArray(value)) return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  if (type === 'object') {
    const keys = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  throw new TypeError(`cannot canonicalize a ${type}`);
}

export function b64url(bytes) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < data.length; i += chunk) {
    binary += String.fromCharCode(...data.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64url(value) {
  const text = String(value).replace(/-/g, '+').replace(/_/g, '/');
  const padded = text + '='.repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function b64urlJson(value) {
  return b64url(utf8(JSON.stringify(value)));
}

export function parseB64urlJson(value) {
  return JSON.parse(new TextDecoder().decode(unb64url(value)));
}

export async function sha256Bytes(input) {
  const data = typeof input === 'string' ? utf8(input) : input;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

export async function sha256B64url(input) {
  return b64url(await sha256Bytes(input));
}

/** Hash of a claim field, with email normalization where appropriate. */
export async function hashField(field, value) {
  const normalized = field === 'email' ? normalizeEmail(value) : String(value);
  return sha256B64url(`${field}:${normalized}`);
}

export function normalizeEmail(email) {
  return String(email ?? '').trim().toLowerCase();
}

export async function providerSubjectHash(provider, subject) {
  return sha256B64url(`${provider}:${String(subject)}`);
}

// ── base58 (for the self-certifying DID identifier) ──────────────────────────

export function base58Encode(bytes) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let zeros = 0;
  while (zeros < data.length && data[zeros] === 0) zeros++;
  let number = 0n;
  for (const byte of data) number = (number << 8n) | BigInt(byte);
  let encoded = '';
  while (number > 0n) {
    encoded = BASE58_ALPHABET[Number(number % 58n)] + encoded;
    number /= 58n;
  }
  return '1'.repeat(zeros) + encoded;
}

export function base58Decode(value) {
  const text = String(value);
  let zeros = 0;
  while (zeros < text.length && text[zeros] === '1') zeros++;
  let number = 0n;
  for (const char of text) {
    const digit = BASE58_MAP.get(char);
    if (digit === undefined) throw new Error('invalid base58 character');
    number = number * 58n + digit;
  }
  const bytes = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 0xffn));
    number >>= 8n;
  }
  return Uint8Array.from([...new Array(zeros).fill(0), ...bytes]);
}

// ── DID derivation ───────────────────────────────────────────────────────────

export function publicJwkOf(jwk) {
  return { kty: jwk?.kty, crv: jwk?.crv, x: jwk?.x, y: jwk?.y };
}

export function isValidPublicJwk(jwk) {
  return Boolean(
    jwk &&
      jwk.kty === 'EC' &&
      jwk.crv === 'P-256' &&
      typeof jwk.x === 'string' &&
      jwk.x.length > 20 &&
      typeof jwk.y === 'string' &&
      jwk.y.length > 20,
  );
}

/** did:byoid:z<base58btc(SHA-256(canonical(public JWK)))> */
export async function didFromPublicJwk(publicJwk) {
  if (!isValidPublicJwk(publicJwk)) throw new Error('a P-256 public JWK is required');
  const digest = await sha256Bytes(canonicalize(publicJwkOf(publicJwk)));
  return `${DID_PREFIX}z${base58Encode(digest)}`;
}

export function isDid(value) {
  return typeof value === 'string' && DID_RE.test(value);
}

export function methodSpecificId(did) {
  if (!isDid(did)) throw new Error('not a did:byoid identifier');
  return did.slice(DID_PREFIX.length);
}

/** Public rholo name where this DID's signed event log is anchored. */
export function anchorName(did, prefix = 'byoid') {
  return `${prefix}:did:${methodSpecificId(did)}`;
}

/** REV addresses are base58check values derived from a secp256k1 key. */
export function isRevAddress(value) {
  return /^[1-9A-HJ-NP-Za-km-z]{45,60}$/.test(String(value || '').trim());
}

/** Public rholo name for a Keybase-style REV proof card. */
export function revAnchorName(address) {
  const value = String(address || '').trim();
  if (!isRevAddress(value)) throw new Error('invalid REV address');
  return `byoid:rev:${value}`;
}

// ── signed events ────────────────────────────────────────────────────────────

export function eventBody(event) {
  const { id, signature, ...body } = event;
  return body;
}

export function eventSigningBytes(event) {
  return utf8(canonicalize(eventBody(event)));
}

export async function eventId(event) {
  return sha256B64url(canonicalize(eventBody(event)));
}

export async function finalizeEvent(body, signatureBytes) {
  return {
    ...body,
    id: await sha256B64url(canonicalize(body)),
    signature: b64url(signatureBytes),
  };
}

async function importPublicKey(publicJwk) {
  return crypto.subtle.importKey(
    'jwk',
    publicJwkOf(publicJwk),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

export async function signEs256(privateKey, bytes) {
  return new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytes),
  );
}

export async function verifyEs256(publicKeyOrJwk, bytes, signature) {
  try {
    const key =
      publicKeyOrJwk instanceof CryptoKey
        ? publicKeyOrJwk
        : await importPublicKey(publicKeyOrJwk);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      signature,
      bytes,
    );
  } catch {
    return false;
  }
}

export async function verifyEventSignature(publicJwk, event) {
  try {
    if (!isValidPublicJwk(publicJwk)) return false;
    if (!event || typeof event.signature !== 'string') return false;
    const expectedId = await eventId(event);
    if (event.id !== expectedId) return false;
    return await verifyEs256(
      publicJwk,
      eventSigningBytes(event),
      unb64url(event.signature),
    );
  } catch {
    return false;
  }
}

function isIsoDate(value) {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isHashB64url(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43,44}$/.test(value);
}

function isSignatureB64url(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{80,128}$/.test(value);
}

/**
 * Structural validation of one event. Signature and chain-position checks are
 * separate so a resolver can report *why* an event was rejected.
 */
export function validateEventShape(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    throw new Error('event must be an object');
  }
  const encodedSize = utf8(canonicalize(event)).length;
  if (encodedSize > MAX_EVENT_BYTES) throw new Error('event is too large');
  if (event.v !== EVENT_VERSION) throw new Error('unsupported event version');
  if (!EVENT_TYPE_LIST.includes(event.type)) throw new Error('unknown event type');
  if (!isDid(event.did)) throw new Error('invalid DID');
  if (!Number.isInteger(event.seq) || event.seq < 1) throw new Error('seq must be a positive integer');
  if (event.seq === 1 && event.prev !== null) throw new Error('the first event must have prev=null');
  if (event.seq > 1 && !isHashB64url(event.prev)) throw new Error('prev must be an event id');
  if (!isIsoDate(event.at)) throw new Error('at must be an ISO date');
  if (!event.payload || typeof event.payload !== 'object' || Array.isArray(event.payload)) {
    throw new Error('payload must be an object');
  }
  if (!isHashB64url(event.id)) throw new Error('id must be a base64url SHA-256 digest');
  if (!isSignatureB64url(event.signature)) throw new Error('signature must be base64url');

  if (event.type === EVENT_TYPES.CREATE) {
    if (event.seq !== 1) throw new Error('a create event must be seq 1');
    if (!isValidPublicJwk(event.payload.publicKeyJwk)) {
      throw new Error('create payload must contain a P-256 publicKeyJwk');
    }
    if (
      event.payload.didDocument &&
      (typeof event.payload.didDocument !== 'object' ||
        event.payload.didDocument.id !== event.did)
    ) {
      throw new Error('create payload didDocument has the wrong id');
    }
    if (
      event.payload.method &&
      (event.payload.method.chain !== undefined && event.payload.method.chain !== 'rholo')
    ) {
      throw new Error('unsupported anchor chain');
    }
  } else if (event.type === EVENT_TYPES.LINK) {
    if (typeof event.payload.provider !== 'string' || !event.payload.provider) {
      throw new Error('link payload needs a provider');
    }
    if (!isHashB64url(event.payload.subjectHash)) {
      throw new Error('link payload needs a subject hash');
    }
    if (!isHashB64url(event.payload.attestationHash)) {
      throw new Error('link payload needs an attestation hash');
    }
    if (!isIsoDate(event.payload.linkedAt)) {
      throw new Error('link payload needs a linkedAt date');
    }
  } else if (event.type === EVENT_TYPES.REVOKE) {
    if (typeof event.payload.credentialId !== 'string' || !event.payload.credentialId) {
      throw new Error('revoke payload needs a credentialId');
    }
    if (!isIsoDate(event.payload.revokedAt)) {
      throw new Error('revoke payload needs a revokedAt date');
    }
  } else if (event.type === EVENT_TYPES.DEACTIVATE) {
    if (!isIsoDate(event.payload.deactivatedAt)) {
      throw new Error('deactivate payload needs a deactivatedAt date');
    }
  }
  return true;
}

// ── DID document / resolution ────────────────────────────────────────────────

export function buildDIDDocument({
  did,
  publicJwk,
  serviceEndpoint,
  createdAt,
  updatedAt,
  links = [],
  revocations = [],
  deactivated = false,
}) {
  const keyId = `${did}#key-1`;
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://byoid.dev/context/v1'],
    id: did,
    controller: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: publicJwkOf(publicJwk),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    service: serviceEndpoint
      ? [
          {
            id: `${did}#byoid-agent`,
            type: 'BYOIDAgent',
            serviceEndpoint,
          },
        ]
      : [],
    created: createdAt,
    updated: updatedAt || createdAt,
    byoid: {
      method: 'did:byoid',
      links,
      revocationCount: revocations.length,
      deactivated,
    },
  };
}

function emptyResolution(did, errors = []) {
  return {
    did,
    status: {
      valid: false,
      forked: false,
      gaps: false,
      deactivated: false,
      eventCount: 0,
      latestSeq: 0,
      latestEventId: null,
      rejectedCount: 0,
      errors,
    },
    didDocument: null,
    events: [],
    rawEvents: [],
    rejected: [],
    publicKeyJwk: null,
    createEvent: null,
    latestEvent: null,
    links: [],
    revocations: [],
    deactivated: false,
  };
}

/**
 * Reduce the data read at a DID's anchor name into one canonical chain.
 *
 * Anybody can write to a public rholo name, so the name is a bulletin board,
 * not an access-controlled registry: integrity comes from the signatures and
 * the hash-linked chain, and invalid/replayed/forked data is reported rather
 * than trusted.
 */
export async function reduceEvents(did, rawEvents) {
  if (!isDid(did)) return emptyResolution(String(did), ['invalid DID']);
  const input = Array.isArray(rawEvents) ? rawEvents : [];
  const rejected = [];
  const creates = [];
  const others = [];
  const seen = new Set();

  for (const event of input) {
    try {
      validateEventShape(event);
      if (event.did !== did) throw new Error('event belongs to a different DID');
      if (seen.has(event.id)) continue;
      const expectedId = await eventId(event);
      if (event.id !== expectedId) throw new Error('event id does not match its content');
      seen.add(event.id);
      if (event.type === EVENT_TYPES.CREATE) {
        const derived = await didFromPublicJwk(event.payload.publicKeyJwk);
        if (derived !== did) throw new Error('DID does not match the create event public key');
        if (!(await verifyEventSignature(event.payload.publicKeyJwk, event))) {
          throw new Error('create event signature is invalid');
        }
        creates.push(event);
      } else {
        others.push(event);
      }
    } catch (error) {
      rejected.push({ id: event?.id || null, reason: error.message });
    }
  }

  if (!creates.length) {
    const resolution = emptyResolution(did, ['no valid create event at this anchor']);
    resolution.rawEvents = input;
    resolution.rejected = rejected;
    resolution.status.rejectedCount = rejected.length;
    return resolution;
  }

  creates.sort((a, b) => String(a.at).localeCompare(String(b.at)) || a.id.localeCompare(b.id));
  const create = creates[0];
  const publicKeyJwk = create.payload.publicKeyJwk;
  const chain = [create];
  const chainIds = new Set([create.id]);
  let forked = false;
  let gaps = false;

  // Extend the chain one sequence number at a time. Invalid signatures and
  // events that do not point at the current tip cannot join the canonical log.
  for (;;) {
    const expectedSeq = chain[chain.length - 1].seq + 1;
    const tip = chain[chain.length - 1];
    const candidates = [];
    for (const event of others) {
      if (chainIds.has(event.id)) continue;
      if (event.seq !== expectedSeq) continue;
      if (event.prev !== tip.id) continue;
      if (await verifyEventSignature(publicKeyJwk, event)) candidates.push(event);
    }
    if (!candidates.length) {
      const higher = others.some((event) => event.seq > expectedSeq);
      if (higher) gaps = true;
      break;
    }
    if (candidates.length > 1) forked = true;
    candidates.sort(
      (a, b) => String(a.at).localeCompare(String(b.at)) || a.id.localeCompare(b.id),
    );
    const chosen = candidates[0];
    chain.push(chosen);
    chainIds.add(chosen.id);
  }

  const links = [];
  const revocations = [];
  let deactivated = false;
  for (const event of chain) {
    if (event.type === EVENT_TYPES.LINK) {
      links.push({
        eventId: event.id,
        seq: event.seq,
        at: event.at,
        provider: event.payload.provider,
        subjectHash: event.payload.subjectHash,
        attestationHash: event.payload.attestationHash,
        linkedAt: event.payload.linkedAt,
      });
    } else if (event.type === EVENT_TYPES.REVOKE) {
      revocations.push({
        eventId: event.id,
        seq: event.seq,
        at: event.at,
        credentialId: event.payload.credentialId,
        revokedAt: event.payload.revokedAt,
        reason: event.payload.reason || null,
      });
    } else if (event.type === EVENT_TYPES.DEACTIVATE) {
      deactivated = true;
    }
  }

  const latestEvent = chain[chain.length - 1];
  const baseDoc =
    create.payload.didDocument && typeof create.payload.didDocument === 'object'
      ? create.payload.didDocument
      : buildDIDDocument({
          did,
          publicJwk: publicKeyJwk,
          serviceEndpoint: create.payload.method?.serviceEndpoint || '',
          createdAt: create.at,
        });

  // The public DID document deliberately contains only hashes of linked
  // accounts, never handles or emails. Those live in the holder's wallet and in
  // selectively disclosed credentials.
  const didDocument = {
    ...baseDoc,
    id: did,
    controller: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: publicJwkOf(publicKeyJwk),
      },
    ],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
    updated: latestEvent.at,
    byoid: {
      method: 'did:byoid',
      anchor: {
        chain: 'rholo',
        network: create.payload.method?.network || null,
        shardId: create.payload.method?.shardId || null,
        name: create.payload.method?.name || anchorName(did),
      },
      links: links.map((link) => ({
        provider: link.provider,
        subjectHash: link.subjectHash,
        attestationHash: link.attestationHash,
        linkedAt: link.linkedAt,
        eventId: link.eventId,
      })),
      revocations: revocations.map((revocation) => ({
        credentialId: revocation.credentialId,
        revokedAt: revocation.revokedAt,
        eventId: revocation.eventId,
      })),
      deactivated,
    },
  };

  const errors = [];
  if (forked) errors.push('multiple valid events extend the same sequence; chose deterministically');
  if (gaps) errors.push('the log contains a sequence gap; later events were not applied');
  if (rejected.length) errors.push(`${rejected.length} invalid event(s) were ignored`);

  return {
    did,
    status: {
      valid: chain.length > 0,
      forked,
      gaps,
      deactivated,
      eventCount: chain.length,
      latestSeq: latestEvent.seq,
      latestEventId: latestEvent.id,
      rejectedCount: rejected.length,
      errors,
    },
    didDocument,
    events: chain,
    rawEvents: input,
    rejected,
    publicKeyJwk,
    createEvent: create,
    latestEvent,
    links,
    revocations,
    deactivated,
  };
}

// ── attestations, credentials, presentations ────────────────────────────────

export async function verifyJws(publicJwk, compact) {
  try {
    const parts = String(compact).split('.');
    if (parts.length !== 3) return { ok: false, error: 'not a compact JWS' };
    const header = parseB64urlJson(parts[0]);
    const payload = parseB64urlJson(parts[1]);
    const signature = unb64url(parts[2]);
    const ok = await verifyEs256(publicJwk, utf8(`${parts[0]}.${parts[1]}`), signature);
    return { ok, header, payload };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

export async function verifyAttestation(publicJwk, compact) {
  const verified = await verifyJws(publicJwk, compact);
  if (!verified.ok) return { ...verified, error: verified.error || 'signature is invalid' };
  if (verified.header.alg !== 'ES256') return { ok: false, error: 'unexpected JWS algorithm' };
  return verified;
}

function proofSigningBytes(document) {
  const { proof, ...body } = document;
  return utf8(canonicalize(body));
}

function pushCheck(checks, id, label, ok, detail = '') {
  checks.push({ id, label, ok: Boolean(ok), detail });
  return ok;
}

/**
 * Verify one account credential against a resolved issuer DID and the agent's
 * public key. Returns a check list suitable for a verifier UI.
 */
export async function verifyCredential({
  credential,
  resolution,
  agentPublicJwk,
  agentKid = 'byoid-agent-1',
  now = Date.now(),
}) {
  const checks = [];
  const claims = [];
  const errors = [];
  const fail = (id, label, detail) => {
    pushCheck(checks, id, label, false, detail);
    errors.push(detail);
  };

  if (
    !credential ||
    typeof credential !== 'object' ||
    !Array.isArray(credential.type) ||
    !credential.type.includes('VerifiableCredential') ||
    !credential.credentialSubject ||
    typeof credential.credentialSubject !== 'object'
  ) {
    fail('credential-shape', 'Credential structure', 'not a Verifiable Credential');
    return { ok: false, checks, claims, errors };
  }
  pushCheck(checks, 'credential-shape', 'Credential structure', true, 'W3C VC shape recognised');

  const issuer = credential.issuer;
  if (!isDid(issuer)) {
    fail('issuer-did', 'Issuer identifier', 'issuer is not a did:byoid identifier');
    return { ok: false, checks, claims, errors };
  }
  pushCheck(checks, 'issuer-did', 'Issuer identifier', true, issuer);

  if (!resolution || resolution.did !== issuer || !resolution.status?.valid) {
    fail(
      'issuer-document',
      'Issuer DID resolved',
      resolution?.status?.errors?.[0] || 'no valid DID event log was found',
    );
    return { ok: false, checks, claims, errors };
  }
  pushCheck(
    checks,
    'issuer-document',
    'Issuer DID resolved',
    true,
    `${resolution.events.length} signed event(s), latest seq ${resolution.status.latestSeq}`,
  );

  if (resolution.deactivated) {
    fail('did-active', 'DID is active', 'the DID has been deactivated');
  } else {
    pushCheck(checks, 'did-active', 'DID is active', true, 'no deactivation event');
  }

  const proof = credential.proof;
  let proofOk = false;
  if (!proof || typeof proof.jws !== 'string') {
    fail('credential-signature', 'Credential signature', 'credential has no proof.jws');
  } else {
    if (
      typeof proof.verificationMethod !== 'string' ||
      !proof.verificationMethod.startsWith(`${issuer}#`)
    ) {
      fail('credential-signature', 'Credential signature', 'proof names a foreign verification method');
    } else {
      proofOk = await verifyEs256(
        resolution.publicKeyJwk,
        proofSigningBytes(credential),
        unb64url(proof.jws),
      );
      pushCheck(
        checks,
        'credential-signature',
        'Credential signed by the DID key',
        proofOk,
        proofOk ? `ES256 · ${proof.verificationMethod}` : 'signature does not verify',
      );
      if (!proofOk) errors.push('credential signature does not verify');
    }
  }

  const subject = credential.credentialSubject;
  if (subject.id !== issuer) {
    fail('subject-binding', 'Subject bound to issuer', 'subject.id does not match issuer');
  } else {
    pushCheck(checks, 'subject-binding', 'Subject bound to issuer', true, subject.id);
  }

  if (credential.expirationDate) {
    const expires = Date.parse(credential.expirationDate);
    const expired = !Number.isNaN(expires) && expires < now;
    if (expired) fail('expiration', 'Not expired', `expired ${credential.expirationDate}`);
    else pushCheck(checks, 'expiration', 'Not expired', true, credential.expirationDate);
  } else {
    pushCheck(checks, 'expiration', 'Not expired', true, 'no expiration date');
  }

  const revoked = (resolution.revocations || []).some(
    (revocation) => revocation.credentialId === credential.id,
  );
  if (revoked) fail('not-revoked', 'Credential not revoked', 'a revocation event is on chain');
  else pushCheck(checks, 'not-revoked', 'Credential not revoked', true, 'no revocation event');

  const accounts = Array.isArray(subject.accounts)
    ? subject.accounts
    : subject.account
      ? [subject.account]
      : [];

  if (!accounts.length) {
    fail('claims', 'Disclosed account claims', 'credential contains no account claims');
  }

  for (let index = 0; index < accounts.length; index++) {
    const account = accounts[index];
    const label = `Account ${index + 1}${account?.provider ? ` · ${account.provider}` : ''}`;
    if (!account || typeof account !== 'object' || typeof account.provider !== 'string') {
      fail(`claim-${index}`, label, 'missing provider');
      continue;
    }
    if (!agentPublicJwk) {
      fail(`attestation-${index}`, `${label} attestation`, 'agent public key is unavailable');
      continue;
    }
    const attestation = await verifyAttestation(agentPublicJwk, account.attestation);
    if (!attestation.ok) {
      fail(`attestation-${index}`, `${label} attestation`, attestation.error || 'invalid attestation');
      continue;
    }
    if (attestation.header.kid && attestation.header.kid !== agentKid) {
      fail(
        `attestation-${index}`,
        `${label} attestation`,
        `unexpected agent key id ${attestation.header.kid}`,
      );
      continue;
    }
    const attestationPayload = attestation.payload;
    if (attestationPayload.iss !== 'byoid:agent') {
      fail(`attestation-${index}`, `${label} attestation`, 'unexpected issuer');
      continue;
    }
    if (attestationPayload.sub !== subject.id) {
      fail(`attestation-${index}`, `${label} attestation`, 'attestation is bound to another DID');
      continue;
    }
    if (attestationPayload.provider !== account.provider) {
      fail(`attestation-${index}`, `${label} attestation`, 'provider mismatch');
      continue;
    }
    pushCheck(
      checks,
      `attestation-${index}`,
      `${label} attestation`,
      true,
      `agent verified via ${attestationPayload.demo ? 'demo ' : ''}${attestationPayload.provider}`,
    );

    const expectedAttestationHash = await sha256B64url(account.attestation);
    if (account.attestationHash !== expectedAttestationHash) {
      fail(`attestation-hash-${index}`, `${label} attestation hash`, 'hash of JWS does not match');
      continue;
    }
    if (account.subjectHash !== attestationPayload.providerSubjectHash) {
      fail(`subject-hash-${index}`, `${label} subject hash`, 'account subject hash does not match');
      continue;
    }

    const link = (resolution.links || []).find(
      (candidate) =>
        candidate.provider === account.provider &&
        candidate.subjectHash === account.subjectHash &&
        candidate.attestationHash === account.attestationHash,
    );
    if (!link) {
      fail(`link-${index}`, `${label} link anchored on rholo`, 'no matching link event');
      continue;
    }
    pushCheck(
      checks,
      `link-${index}`,
      `${label} link anchored on rholo`,
      true,
      `seq ${link.seq} · ${link.linkedAt}`,
    );

    const fieldChecks = [];
    if (account.handle !== undefined) {
      const ok = (await hashField('handle', account.handle)) === attestationPayload.handleHash;
      fieldChecks.push(['handle', ok]);
    }
    if (account.email !== undefined && account.email !== null) {
      const ok = (await hashField('email', account.email)) === attestationPayload.emailHash;
      fieldChecks.push(['email', ok]);
    }
    if (account.name !== undefined) {
      const ok = (await hashField('name', account.name)) === attestationPayload.nameHash;
      fieldChecks.push(['name', ok]);
    }
    if (account.avatarUrl !== undefined && account.avatarUrl !== null) {
      const ok = (await hashField('avatarUrl', account.avatarUrl)) === attestationPayload.avatarHash;
      fieldChecks.push(['avatarUrl', ok]);
    }
    if (account.emailVerified !== undefined) {
      fieldChecks.push(['emailVerified', account.emailVerified === attestationPayload.emailVerified]);
    }
    if (account.verifiedAt !== undefined && account.verifiedAt !== link.linkedAt) {
      fieldChecks.push(['verifiedAt', false]);
    }
    const fieldsOk = fieldChecks.every(([, ok]) => ok);
    pushCheck(
      checks,
      `fields-${index}`,
      `${label} disclosed fields match the attestation`,
      fieldsOk,
      fieldsOk
        ? fieldChecks.map(([field]) => field).join(', ') || 'no optional fields'
        : `mismatch: ${fieldChecks.filter(([, ok]) => !ok).map(([field]) => field).join(', ')}`,
    );
    if (!fieldsOk) errors.push(`${label} has a disclosed field that does not match its attestation`);

    const disclosedFields = [];
    for (const field of ['handle', 'email', 'name', 'avatarUrl', 'emailVerified', 'verifiedAt']) {
      if (account[field] !== undefined && account[field] !== null) disclosedFields.push(field);
    }
    const hiddenFields = ['handle', 'email', 'name', 'avatarUrl'].filter(
      (field) => !disclosedFields.includes(field),
    );
    claims.push({
      provider: account.provider,
      handle: account.handle ?? null,
      email: account.email ?? null,
      emailVerified:
        account.emailVerified === undefined
          ? attestationPayload.emailVerified
          : account.emailVerified,
      verifiedAt: account.verifiedAt ?? link.linkedAt,
      subjectHash: account.subjectHash,
      demo: Boolean(attestationPayload.demo),
      disclosedFields,
      hiddenFields,
    });
  }

  const ok = checks.every((check) => check.ok);
  return { ok, checks, claims, errors };
}

function presentationSigningBytes(presentation) {
  const { proof, ...body } = presentation;
  return utf8(canonicalize(body));
}

/**
 * Verify a BYOID presentation. `resolveDid(did)` must return a resolution from
 * reduceEvents() (usually via GET /api/did/:did).
 */
export async function verifyPresentation({
  presentation,
  resolveDid,
  agentPublicJwk,
  agentKid = 'byoid-agent-1',
  now = Date.now(),
}) {
  const checks = [];
  const errors = [];
  const credentialResults = [];
  const fail = (id, label, detail) => {
    pushCheck(checks, id, label, false, detail);
    errors.push(detail);
  };

  if (
    !presentation ||
    typeof presentation !== 'object' ||
    !Array.isArray(presentation.type) ||
    !presentation.type.includes('VerifiablePresentation') ||
    !Array.isArray(presentation.verifiableCredential)
  ) {
    fail('presentation-shape', 'Presentation structure', 'not a Verifiable Presentation');
    return { ok: false, checks, errors, credentials: [] };
  }
  pushCheck(
    checks,
    'presentation-shape',
    'Presentation structure',
    true,
    `${presentation.verifiableCredential.length} credential(s)`,
  );

  const holder = presentation.holder;
  if (!isDid(holder)) {
    fail('holder-did', 'Holder identifier', 'holder is not a did:byoid identifier');
    return { ok: false, checks, errors, credentials: [] };
  }
  const holderResolution = await resolveDid(holder);
  if (!holderResolution || !holderResolution.status?.valid) {
    fail('holder-document', 'Holder DID resolved', 'no valid holder DID event log');
  } else {
    pushCheck(checks, 'holder-document', 'Holder DID resolved', true, holder);
  }

  const proof = presentation.proof;
  if (!proof || typeof proof.jws !== 'string' || !holderResolution?.publicKeyJwk) {
    fail('presentation-signature', 'Presentation signed by the holder', 'missing proof or holder key');
  } else {
    const proofOk = await verifyEs256(
      holderResolution.publicKeyJwk,
      presentationSigningBytes(presentation),
      unb64url(proof.jws),
    );
    pushCheck(
      checks,
      'presentation-signature',
      'Presentation signed by the holder',
      proofOk,
      proofOk ? 'ES256 signature verifies' : 'signature does not verify',
    );
    if (!proofOk) errors.push('presentation signature does not verify');
  }

  for (let index = 0; index < presentation.verifiableCredential.length; index++) {
    const credential = presentation.verifiableCredential[index];
    const issuer = credential?.issuer;
    let resolution = null;
    if (isDid(issuer)) resolution = await resolveDid(issuer);
    if (!resolution || !resolution.status?.valid) {
      fail(`credential-${index}-issuer`, `Credential ${index + 1} issuer`, 'issuer DID did not resolve');
    }
    const result = await verifyCredential({
      credential,
      resolution,
      agentPublicJwk,
      agentKid,
      now,
    });
    credentialResults.push(result);
    if (!result.ok) {
      for (const error of result.errors) errors.push(`credential ${index + 1}: ${error}`);
    }
    pushCheck(
      checks,
      `credential-${index}`,
      `Credential ${index + 1} verified`,
      result.ok,
      result.ok ? `${result.claims.length} disclosed account(s)` : result.errors[0] || 'failed',
    );
  }

  return {
    ok: checks.every((check) => check.ok) && credentialResults.every((result) => result.ok),
    checks,
    errors,
    credentials: credentialResults,
    holder,
  };
}

// ── small helpers ────────────────────────────────────────────────────────────

export function shortId(value, head = 10, tail = 6) {
  const text = String(value ?? '');
  if (text.length <= head + tail + 1) return text;
  return `${text.slice(0, head)}…${text.slice(-tail)}`;
}

export function eventTypeLabel(type) {
  switch (type) {
    case EVENT_TYPES.CREATE:
      return 'DID created';
    case EVENT_TYPES.LINK:
      return 'Account linked';
    case EVENT_TYPES.REVOKE:
      return 'Credential revoked';
    case EVENT_TYPES.DEACTIVATE:
      return 'DID deactivated';
    default:
      return type;
  }
}
