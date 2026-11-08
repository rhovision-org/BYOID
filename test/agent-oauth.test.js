import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import { Agent } from '../src/agent.js';
import { generateAgentKey, jwsSign } from '../src/crypto.js';
import {
  PROVIDER_CATALOG,
  appleClientSecret,
  buildAuthorizationUrl,
  demoProfile,
  exchangeCode,
  fetchProfile,
  publicProviderInfo,
  verifyAppleIdToken,
} from '../src/providers.js';
import { didFromPublicJwk, publicJwkOf } from '../public/shared.js';

async function makeDid() {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const publicJwk = publicJwkOf(await crypto.subtle.exportKey('jwk', pair.publicKey));
  return { pair, publicJwk, did: await didFromPublicJwk(publicJwk) };
}

test('agent attestations carry hashes, never raw profile values', async () => {
  const key = await generateAgentKey();
  const agent = new Agent({ key, enabled: false });
  const identity = await makeDid();
  const profile = {
    provider: 'google',
    subject: 'demo-google-ada-1001',
    handle: 'ada.demo',
    name: 'Ada Demo',
    email: 'ada.demo@example.com',
    emailVerified: true,
    avatarUrl: null,
  };
  const attestation = await agent.signAttestation({ ...profile, demo: true }, identity.did);
  assert.equal(attestation.provider, 'google');
  assert.equal(attestation.attestation.split('.').length, 3);
  assert.equal(attestation.subjectHash.length > 40, true);
  const serialized = JSON.stringify(attestation.payload);
  for (const secret of [profile.email, profile.handle, profile.name, profile.subject]) {
    assert.equal(serialized.includes(secret), false, `${secret} must not appear in the attestation`);
  }
  const verified = await agent.verifyAttestation(attestation.attestation);
  assert.equal(verified.ok, true);
  assert.equal(verified.payload.sub, identity.did);
  assert.equal(verified.payload.demo, true);

  const tampered = attestation.attestation.split('.');
  tampered[1] = Buffer.from(JSON.stringify({ ...verified.payload, demo: false })).toString(
    'base64url',
  );
  assert.equal((await agent.verifyAttestation(tampered.join('.'))).ok, false);
});

test('the agent anchor record is self-signed and verifiable', async () => {
  const key = await generateAgentKey();
  const agent = new Agent({ key, enabled: false });
  const record = await agent.buildAnchorRecord({ network: 'playground', shardId: '/playground' });
  assert.equal(record.type, 'byoid.agent.key');
  assert.equal(await agent.verifyAnchorRecord(record), true);
  const tampered = JSON.parse(JSON.stringify(record));
  tampered.kid = 'other';
  assert.equal(await agent.verifyAnchorRecord(tampered), false);
});

test('authorization URLs carry state, PKCE and the redirect URI', () => {
  const google = PROVIDER_CATALOG.google;
  const url = new URL(
    buildAuthorizationUrl(
      google,
      { clientId: 'client-1' },
      {
        state: 'state-123',
        codeChallenge: 'challenge-456',
        redirectUri: 'http://localhost:3000/auth/google/callback',
      },
    ),
  );
  assert.equal(url.searchParams.get('client_id'), 'client-1');
  assert.equal(url.searchParams.get('state'), 'state-123');
  assert.equal(url.searchParams.get('code_challenge'), 'challenge-456');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('redirect_uri'), 'http://localhost:3000/auth/google/callback');
  assert.match(url.searchParams.get('scope'), /openid/);
});

test('token exchange sends the code verifier', async () => {
  let captured;
  const response = await exchangeCode(
    PROVIDER_CATALOG.google,
    { clientId: 'id', clientSecret: 'secret' },
    {
      code: 'code-1',
      codeVerifier: 'verifier-1',
      redirectUri: 'http://localhost:3000/auth/google/callback',
      fetchImpl: async (url, init) => {
        captured = init.body.toString();
        return new Response(JSON.stringify({ access_token: 'token' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    },
  );
  assert.equal(response.access_token, 'token');
  assert.match(captured, /code_verifier=verifier-1/);
  assert.match(captured, /client_secret=secret/);
});

test('Google, GitHub and Facebook profiles normalize to one shape', async () => {
  const google = await fetchProfile(
    PROVIDER_CATALOG.google,
    { access_token: 't' },
    {
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            sub: 'g-1',
            email: 'Alice@Example.com',
            email_verified: true,
            name: 'Alice',
            picture: 'https://example.com/a.png',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    },
  );
  assert.deepEqual(google, {
    provider: 'google',
    subject: 'g-1',
    handle: 'Alice',
    name: 'Alice',
    email: 'Alice@Example.com',
    emailVerified: true,
    avatarUrl: 'https://example.com/a.png',
  });

  const github = await fetchProfile(
    PROVIDER_CATALOG.github,
    { access_token: 't' },
    {
      fetchImpl: async (url) => {
        const path = new URL(url).pathname;
        if (path === '/user') {
          return new Response(
            JSON.stringify({ id: 42, login: 'octo', name: 'Octo', email: null, avatar_url: 'x' }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        return new Response(
          JSON.stringify([{ email: 'octo@example.com', primary: true, verified: true }]),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      },
    },
  );
  assert.equal(github.provider, 'github');
  assert.equal(github.subject, '42');
  assert.equal(github.handle, 'octo');
  assert.equal(github.email, 'octo@example.com');
  assert.equal(github.emailVerified, true);

  const facebook = await fetchProfile(
    PROVIDER_CATALOG.facebook,
    { access_token: 't' },
    {
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            id: 'fb-1',
            name: 'Ada',
            email: 'ada@example.com',
            picture: { data: { url: 'https://example.com/fb.png' } },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    },
  );
  assert.equal(facebook.provider, 'facebook');
  assert.equal(facebook.subject, 'fb-1');
  assert.equal(facebook.handle, 'Ada');
  assert.equal(facebook.emailVerified, false, 'Graph API does not assert email verification');
});

test('demo profiles are marked and public provider info has no secret', () => {
  const profile = demoProfile('google', 'google-ada');
  assert.equal(profile.provider, 'google');
  assert.equal(profile.email, 'ada.demo@example.com');
  const info = publicProviderInfo(
    PROVIDER_CATALOG.google,
    false,
    'demo',
    'http://localhost:3000/auth/google/callback',
  );
  assert.equal(info.mode, 'demo');
  assert.equal(JSON.stringify(info).includes('clientSecretValue'), false);
  assert.equal(info.configure.redirectUri, 'http://localhost:3000/auth/google/callback');
});

test('Apple authorization URL carries a nonce and query response mode', () => {
  const url = new URL(
    buildAuthorizationUrl(
      PROVIDER_CATALOG.apple,
      { clientId: 'com.example.byoid.web' },
      {
        state: 'state-apple',
        redirectUri: 'https://example.com/auth/apple/callback',
        nonce: 'nonce-apple',
      },
    ),
  );
  assert.equal(url.origin, 'https://appleid.apple.com');
  assert.equal(url.searchParams.get('response_mode'), 'query');
  assert.equal(url.searchParams.get('nonce'), 'nonce-apple');
  assert.equal(url.searchParams.get('code_challenge'), null);
});

test('Apple client secret is a valid ES256 JWT for the Services ID', () => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const secret = appleClientSecret(
    PROVIDER_CATALOG.apple,
    {
      clientId: 'com.example.byoid.web',
      appleTeamId: 'TEAM123456',
      appleKeyId: 'KEY1234567',
      applePrivateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    },
    { now: 1_700_000_000 },
  );
  const [headerPart, payloadPart] = secret.split('.');
  const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString());
  const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString());
  assert.equal(header.alg, 'ES256');
  assert.equal(header.kid, 'KEY1234567');
  assert.equal(payload.iss, 'TEAM123456');
  assert.equal(payload.sub, 'com.example.byoid.web');
  assert.equal(payload.aud, 'https://appleid.apple.com');
  assert.equal(payload.exp > payload.iat, true);
});

test('Apple identity tokens are verified and normalized without exposing the token', async () => {
  const key = await generateAgentKey();
  const now = Math.floor(Date.now() / 1000);
  const idToken = await jwsSign(key.privateJwk, 'apple-key-1', {
    iss: 'https://appleid.apple.com',
    aud: 'com.example.byoid.web',
    exp: now + 600,
    iat: now,
    nonce: 'nonce-123',
    sub: 'apple-subject-1',
    email: 'ada@example.com',
    email_verified: 'true',
  });
  const fetchImpl = async () =>
    new Response(JSON.stringify({ keys: [{ ...key.publicJwk, kid: 'apple-key-1' }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  const claims = await verifyAppleIdToken(idToken, {
    clientId: 'com.example.byoid.web',
    nonce: 'nonce-123',
    fetchImpl,
  });
  assert.equal(claims.sub, 'apple-subject-1');
  const profile = await fetchProfile(
    PROVIDER_CATALOG.apple,
    {
      id_token: idToken,
      clientId: 'com.example.byoid.web',
      nonce: 'nonce-123',
      user: JSON.stringify({ name: { firstName: 'Ada', lastName: 'Lovelace' } }),
    },
    { fetchImpl },
  );
  assert.deepEqual(profile, {
    provider: 'apple',
    subject: 'apple-subject-1',
    handle: 'ada',
    name: 'Ada Lovelace',
    email: 'ada@example.com',
    emailVerified: true,
    avatarUrl: null,
  });
  await assert.rejects(
    verifyAppleIdToken(idToken, {
      clientId: 'com.example.byoid.web',
      nonce: 'wrong-nonce',
      fetchImpl,
    }),
    /nonce/,
  );
});
