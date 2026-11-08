// Server-side cryptography: rholo deploy signing, REV addresses, P-256 agent
// keys and ES256 JWS. Browser-side primitives live in public/shared.js.

import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { blake2b } from '@noble/hashes/blake2b';
import { keccak_256 } from '@noble/hashes/sha3';
import bs58 from 'bs58';
import { canonicalize, isValidPublicJwk } from '../public/shared.js';

export { isValidPublicJwk };

const subtle = globalThis.crypto.subtle;

export const utf8 = (value) => new TextEncoder().encode(value);
export const hex = (bytes) => Buffer.from(bytes).toString('hex');
export const unhex = (value) => Uint8Array.from(Buffer.from(String(value), 'hex'));

export function base64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function unbase64url(value) {
  return Uint8Array.from(Buffer.from(String(value), 'base64url'));
}

export const unb64url = unbase64url;

export function sha256Bytes(input) {
  return Uint8Array.from(createHash('sha256').update(input).digest());
}

export function sha256Hex(input) {
  return hex(sha256Bytes(input));
}

export function sha256B64url(input) {
  return base64url(sha256Bytes(input));
}

export function randomBase64Url(byteLength = 32) {
  return randomBytes(byteLength).toString('base64url');
}

export function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/** PKCE S256: BASE64URL(SHA256(ASCII(code_verifier))). */
export function pkceChallenge(verifier) {
  return sha256B64url(verifier);
}

// ── rholo / REV ──────────────────────────────────────────────────────────────

/**
 * REV address derivation, matching rholo's `RevAddress::from_public_key`:
 *   keccak256(uncompressed pubkey without 0x04) → last 20 bytes
 *   key_hash = keccak256(eth address)
 *   payload  = 00000000 || key_hash
 *   checksum = first 4 bytes of blake2b256(payload)
 *   address  = base58(payload || checksum)
 */
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
    throw new Error('Invalid secp256k1 private key');
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

/**
 * Protobuf encoding of DeployDataProto (casper.proto), fields in ascending
 * order, which is what prost's deterministic encoding produces. The signature
 * is over BLAKE2b-256 of exactly these bytes — see rholo's Signed<DeployData>.
 */
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

/** Sign deploy data, returning the BLAKE2b-256 hash and DER signature (hex). */
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

// ── P-256 agent keys / ES256 ─────────────────────────────────────────────────

export function publicJwkOf(jwk) {
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

export async function generateAgentKey() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const privateJwk = await subtle.exportKey('jwk', pair.privateKey);
  const publicJwk = publicJwkOf(await subtle.exportKey('jwk', pair.publicKey));
  return { privateJwk, publicJwk, createdAt: new Date().toISOString() };
}

export async function importPrivateJwk(jwk) {
  return subtle.importKey(
    'jwk',
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
}

export async function importPublicJwk(jwk) {
  return subtle.importKey(
    'jwk',
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

export async function signEs256(privateJwk, bytes) {
  const key = await importPrivateJwk(privateJwk);
  return new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, bytes));
}

export async function verifyEs256(publicJwk, bytes, signature) {
  try {
    const key = await importPublicJwk(publicJwk);
    return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, bytes);
  } catch {
    return false;
  }
}

export function jwkFingerprint(publicJwk) {
  return `sha256:${sha256B64url(canonicalize(publicJwkOf(publicJwk)))}`;
}

export async function jwsSign(privateJwk, kid, payload) {
  const header = { alg: 'ES256', typ: 'JWT', kid };
  const signingInput = `${base64url(utf8(JSON.stringify(header)))}.${base64url(
    utf8(canonicalize(payload)),
  )}`;
  const signature = await signEs256(privateJwk, utf8(signingInput));
  return `${signingInput}.${base64url(signature)}`;
}

export async function jwsVerify(publicJwk, compact) {
  try {
    const parts = String(compact).split('.');
    if (parts.length !== 3) return { ok: false, error: 'not a compact JWS' };
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const signature = Buffer.from(parts[2], 'base64url');
    const ok = await verifyEs256(
      publicJwk,
      utf8(`${parts[0]}.${parts[1]}`),
      Uint8Array.from(signature),
    );
    return { ok, header, payload };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}
